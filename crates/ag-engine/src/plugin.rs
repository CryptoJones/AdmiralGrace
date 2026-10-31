//! The plugin SDK: the points where a loader, an architecture or a tool is
//! added without forking.
//!
//! Three things are extended. A **loader** reads a container the engine
//! does not — a firmware image with its own header, a game's archive, a
//! packed format — into the sections, symbols and entry point every other
//! part works from. An **architecture** decodes the code of a language the
//! engine does not, into the instructions and the flow between them that
//! the control-flow walk, the listing and the graph work from. A **tool**
//! is an analysis of its own over an open image, run from the command line
//! (`ag tool`) or by a language model through the MCP server; its trait
//! lives in `ag_image::plugin`, beside the image it reads.
//!
//! A plugin is written one of two ways. In Rust, a crate that builds on
//! the engine implements [`Loader`] or [`Architecture`] and registers it
//! ([`register_loader`], [`register_architecture`]) before an image is
//! opened; the workbench and the command line are such crates, and read
//! the manifests as they start. In any language, a plugin is a command
//! declared in a manifest — a JSON file in a plugin directory
//! ([`manifest_dirs`]) — that the `ag` binary finds as it starts and runs
//! when it is needed, speaking JSON over its standard streams
//! ([`ExternalLoader`], [`ExternalArchitecture`], the tool's counterpart in
//! `ag_image`). The manifest and the three conversations are described in
//! `docs/plugins.md`.
//!
//! The registry is one for the process: a plugin registered is there for
//! every image opened after, and one registered under a name already taken
//! replaces it. A registered loader is offered a file before the engine's
//! own loaders; one that fails is reported, and the engine's loaders read
//! the file after all.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::arch::Bitness;
use crate::ast::AstNode;
use crate::cfg::ProcedureCfg;
use crate::cpu_context::{DecodedInsn, Flow};
use crate::image::Section;
use crate::lift::{NotLifted, Statement, StatementKind, Variable};
use crate::pipeline::Disasm;
use crate::structure::{Node, Terminator};

/// What a loader reads out of a container: everything the engine needs to
/// know about an image that it would otherwise ask the container for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadedImage {
    /// The language id the code decodes under, such as
    /// `x86:LE:64:default:gcc`, or one a registered architecture names.
    pub language: String,
    /// The entry point, when the container declares one.
    pub entry: Option<u64>,
    /// The address the image is loaded at, when the format has one to
    /// move; a rebase moves the whole image from it.
    pub base: Option<u64>,
    /// The sections, with where each sits in the file: a section without a
    /// `file_offset` has no bytes, and so no code to list.
    pub sections: Vec<Section>,
    /// The function symbols, as `(address, name)`.
    pub functions: Vec<(u64, String)>,
    /// The data symbols, as `(address, name, size)`.
    pub data: Vec<(u64, String, u64)>,
    /// The import slots, as `(slot address, imported name)`.
    pub imports: Vec<(u64, String)>,
}

/// A reader of a container the engine does not read itself.
pub trait Loader: Send + Sync {
    /// The loader's name, as `ag plugins` lists it.
    fn name(&self) -> &str;
    /// Whether these are the loader's bytes: a check of the magic, cheap,
    /// asked of every loader for every file opened.
    fn recognizes(&self, bytes: &[u8]) -> bool;
    /// Read the container.
    fn load(&self, name: &str, bytes: &[u8]) -> Result<LoadedImage, String>;
}

/// The instructions of one section, decoded, with the text of each.
#[derive(Debug, Default)]
pub struct DecodedSection {
    /// The instructions, in address order, with the flow of each — what
    /// the control-flow walk follows.
    pub disasm: Disasm,
    /// The mnemonic, the operands and the registers named, by address.
    pub text: HashMap<u64, (String, String, Vec<String>)>,
}

/// A decoder of a language the engine does not decode itself.
pub trait Architecture: Send + Sync {
    /// The architecture's name, as `ag plugins` lists it.
    fn name(&self) -> &str;
    /// The language ids it decodes.
    fn languages(&self) -> Vec<String>;
    /// The width of addresses under `language`.
    fn bitness(&self, language: &str) -> Bitness;
    /// Decode the bytes of one section loaded at `base`.
    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String>;
    /// Whether the architecture lifts the functions of `language` itself
    /// ([`Architecture::lift`]); the engine's lifter reads x86-64 alone, so
    /// an image of another language has pseudocode only through this.
    fn lifts(&self, _language: &str) -> bool {
        false
    }
    /// The basic blocks of the function entered at `entry`, when the
    /// architecture recovers them itself — an instruction set with delay
    /// slots, hardware loops or a bytecode whose flow the decoder's `Flow`
    /// cannot say; `None` leaves the walk to the engine, which follows the
    /// flows. The blocks are in address order, each ending where the next
    /// begins or the code does.
    fn blocks(
        &self,
        _language: &str,
        _disasm: &Disasm,
        _entry: u64,
    ) -> Option<Result<Vec<RecoveredBlock>, String>> {
        None
    }
    /// Lift a whole function at once, with the context an instruction alone
    /// does not have, to the medium level: blocks of statements over
    /// variables, each ending in a return, a goto, a branch or a switch.
    /// The engine structures the graph into pseudocode and gives it its
    /// levels, after the registered rewriters. `None` leaves the function
    /// to the engine's lifter; `Err` refuses it with the reason.
    fn lift(&self, _function: &FunctionCode) -> Option<Result<LiftedGraph, String>> {
        None
    }
}

/// A basic block an architecture recovered itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredBlock {
    /// The address of the first instruction.
    pub from: u64,
    /// The address after the last instruction.
    pub to: u64,
    /// The addresses of the blocks control can go on to; none for a block
    /// that returns or ends the procedure.
    pub successors: Vec<u64>,
    /// The functions the block calls, by address.
    pub calls: Vec<u64>,
}

/// A function an architecture lifted itself, at the medium level.
#[derive(Debug, Clone)]
pub struct LiftedGraph {
    /// The C return type: `void` when nothing is returned.
    pub return_type: String,
    /// The parameters, in order.
    pub params: Vec<Variable>,
    /// The locals, in the order they are declared.
    pub locals: Vec<Variable>,
    /// The index of the node the function is entered at.
    pub entry: usize,
    /// The nodes: each with the address that labels it, its statements and
    /// how it leaves.
    pub nodes: Vec<Node>,
    /// The instructions no statement came from: the frame, the no-ops.
    pub frame: Vec<u64>,
}

/// What an architecture is handed to lift a function.
#[derive(Debug, Clone, Copy)]
pub struct FunctionCode<'a> {
    pub language: &'a str,
    /// The function's entry address.
    pub address: u64,
    pub name: &'a str,
    /// The decoded instructions of the function's section.
    pub disasm: &'a Disasm,
    /// The function's control-flow graph: the architecture's own blocks
    /// when it recovered them, the engine's walk otherwise.
    pub cfg: &'a ProcedureCfg,
    /// The section's bytes, from `base`.
    pub bytes: &'a [u8],
    pub base: u64,
}

/// A rewriter changes a function's medium-level graph — the blocks of
/// statements over variables, each ending in a return, a goto, a branch or
/// a switch — after the lifter has built it and before it is structured
/// into pseudocode: it may edit, remove, copy or add statements, add
/// blocks, and point the gotos and branches elsewhere. Control-flow
/// unflattening is the kind of thing it is for. Every function lifted
/// passes through every registered rewriter in order; what one leaves is
/// what the medium and high levels, and the pseudocode, show.
pub trait Rewriter: Send + Sync {
    /// The rewriter's name.
    fn name(&self) -> &str;
    /// Whether the rewriter wants the function at `address` named `name`;
    /// every function, unless said. A rewriter that is a command is not
    /// started for a function it does not want.
    fn wants(&self, _address: u64, _name: &str) -> bool {
        true
    }
    /// Rewrite the graph, or fail with a reason: the function is then not
    /// lifted, and the reason is told with the rewriter's name.
    fn rewrite(&self, rewrite: &mut Rewrite) -> Result<(), String>;
}

/// A function's medium-level graph under rewriting: the nodes, by index,
/// with the entry's; the helpers keep the graph pointing at itself.
#[derive(Debug, Clone)]
pub struct Rewrite {
    /// The function's address.
    pub function: u64,
    /// The function's name.
    pub name: String,
    /// The index of the node the function is entered at.
    entry: usize,
    /// The nodes: each with the address that labels it, its statements and
    /// how it leaves.
    pub nodes: Vec<Node>,
    changed: bool,
}

impl Rewrite {
    /// A graph to rewrite, for a rewriter run outside a lift.
    pub fn new(function: u64, name: &str, entry: usize, nodes: Vec<Node>) -> Self {
        Self {
            function,
            name: name.to_string(),
            entry,
            nodes,
            changed: false,
        }
    }

    /// The index of the node the function is entered at; a rewriter cannot
    /// move it.
    pub fn entry(&self) -> usize {
        self.entry
    }

    /// Whether anything was changed through the helpers, or marked so.
    pub fn changed(&self) -> bool {
        self.changed
    }

    /// Say the nodes were changed by hand, so the graph is analyzed again.
    pub fn mark_changed(&mut self) {
        self.changed = true;
    }

    /// A plain statement of an expression, from the addresses given.
    pub fn statement(node: AstNode, addresses: Vec<u64>) -> Statement {
        Statement {
            node,
            addresses,
            kind: StatementKind::Plain,
        }
    }

    /// An address no node has, for a block the rewriter adds: one past the
    /// highest in the graph — a label, not an instruction's address.
    pub fn fresh_address(&self) -> u64 {
        self.nodes
            .iter()
            .map(|node| node.address)
            .max()
            .map_or(self.function, |most| most.saturating_add(1))
    }

    /// Add a block; its index, for the gotos that lead to it. The address
    /// labels the block, so one another block has is refused.
    pub fn add_block(
        &mut self,
        address: u64,
        statements: Vec<Statement>,
        terminator: Terminator,
    ) -> Result<usize, String> {
        if let Some(taken) = self.nodes.iter().position(|node| node.address == address) {
            return Err(format!(
                "block {taken} has the address {address:#x} already"
            ));
        }
        let count = self.nodes.len();
        for target in terminator.successors() {
            if target > count {
                return Err(format!("no block {target}: there are {count}"));
            }
        }
        self.nodes.push(Node {
            address,
            statements,
            terminator,
        });
        self.changed = true;
        Ok(count)
    }

    fn node_mut(&mut self, block: usize) -> Result<&mut Node, String> {
        let count = self.nodes.len();
        self.nodes
            .get_mut(block)
            .ok_or_else(|| format!("no block {block}: there are {count}"))
    }

    /// A copy of one statement of a block.
    pub fn copy_statement(&self, block: usize, index: usize) -> Result<Statement, String> {
        let node = self
            .nodes
            .get(block)
            .ok_or_else(|| format!("no block {block}: there are {}", self.nodes.len()))?;
        node.statements
            .get(index)
            .cloned()
            .ok_or_else(|| format!("block {block} has no statement {index}"))
    }

    /// Take one statement out of a block.
    pub fn remove_statement(&mut self, block: usize, index: usize) -> Result<Statement, String> {
        let node = self.node_mut(block)?;
        if index >= node.statements.len() {
            return Err(format!("block {block} has no statement {index}"));
        }
        let statement = node.statements.remove(index);
        self.changed = true;
        Ok(statement)
    }

    /// Put a statement into a block at `index`, or at its end when `index`
    /// is past the last.
    pub fn insert_statement(
        &mut self,
        block: usize,
        index: usize,
        statement: Statement,
    ) -> Result<(), String> {
        let node = self.node_mut(block)?;
        let at = index.min(node.statements.len());
        node.statements.insert(at, statement);
        self.changed = true;
        Ok(())
    }

    /// Point every way out of `block` that led to `from` at `to`.
    pub fn redirect(&mut self, block: usize, from: usize, to: usize) -> Result<(), String> {
        let count = self.nodes.len();
        if to >= count {
            return Err(format!("no block {to}: there are {count}"));
        }
        if from == to {
            return Ok(());
        }
        let node = self.node_mut(block)?;
        let mut hit = false;
        let mut point = |target: &mut usize| {
            if *target == from {
                *target = to;
                hit = true;
            }
        };
        match &mut node.terminator {
            Terminator::Return => {}
            Terminator::Goto { target, .. } => point(target),
            Terminator::Branch { taken, next, .. } => {
                point(taken);
                point(next);
            }
            Terminator::Switch { cases, .. } => {
                for (_, target) in cases {
                    point(target);
                }
            }
        }
        if !hit {
            return Err(format!("block {block} does not lead to block {from}"));
        }
        self.changed = true;
        Ok(())
    }

    /// Make `block` go straight to `target`.
    pub fn set_goto(&mut self, block: usize, target: usize) -> Result<(), String> {
        let count = self.nodes.len();
        if target >= count {
            return Err(format!("no block {target}: there are {count}"));
        }
        let node = self.node_mut(block)?;
        let addresses = terminator_addresses(&node.terminator);
        node.terminator = Terminator::Goto { target, addresses };
        self.changed = true;
        Ok(())
    }

    /// Make `block` return.
    pub fn set_return(&mut self, block: usize) -> Result<(), String> {
        let node = self.node_mut(block)?;
        node.terminator = Terminator::Return;
        self.changed = true;
        Ok(())
    }

    /// Make `block` branch on `cond`: to `taken` when it holds, else to
    /// `next`.
    pub fn set_branch(
        &mut self,
        block: usize,
        cond: AstNode,
        taken: usize,
        next: usize,
    ) -> Result<(), String> {
        let count = self.nodes.len();
        for target in [taken, next] {
            if target >= count {
                return Err(format!("no block {target}: there are {count}"));
            }
        }
        let node = self.node_mut(block)?;
        let addresses = terminator_addresses(&node.terminator);
        node.terminator = Terminator::Branch {
            cond,
            taken,
            next,
            addresses,
        };
        self.changed = true;
        Ok(())
    }

    /// Give `block` a terminator of the rewriter's own making.
    pub fn set_terminator(&mut self, block: usize, terminator: Terminator) -> Result<(), String> {
        let count = self.nodes.len();
        for target in terminator.successors() {
            if target >= count {
                return Err(format!("no block {target}: there are {count}"));
            }
        }
        self.node_mut(block)?.terminator = terminator;
        self.changed = true;
        Ok(())
    }

    /// Drop the blocks the entry no longer reaches, renumbering the rest;
    /// how many went. A block cut off by a redirect or a goto stays in the
    /// graph until this is called, so a rewriter can still copy from it.
    pub fn prune_unreachable(&mut self) -> usize {
        let count = self.nodes.len();
        if self.entry >= count {
            return 0;
        }
        let mut reached = vec![false; count];
        let mut work = vec![self.entry];
        while let Some(block) = work.pop() {
            if reached[block] {
                continue;
            }
            reached[block] = true;
            for target in self.nodes[block].terminator.successors() {
                if target < count && !reached[target] {
                    work.push(target);
                }
            }
        }
        let gone = reached.iter().filter(|kept| !**kept).count();
        if gone == 0 {
            return 0;
        }
        let mut renumbered = vec![usize::MAX; count];
        let mut next = 0;
        for (index, kept) in reached.iter().enumerate() {
            if *kept {
                renumbered[index] = next;
                next += 1;
            }
        }
        let point = |target: &mut usize| {
            if *target < count && renumbered[*target] != usize::MAX {
                *target = renumbered[*target];
            }
        };
        let mut nodes = Vec::with_capacity(next);
        for (index, mut node) in std::mem::take(&mut self.nodes).into_iter().enumerate() {
            if !reached[index] {
                continue;
            }
            match &mut node.terminator {
                Terminator::Return => {}
                Terminator::Goto { target, .. } => point(target),
                Terminator::Branch { taken, next, .. } => {
                    point(taken);
                    point(next);
                }
                Terminator::Switch { cases, .. } => {
                    for (_, target) in cases {
                        point(target);
                    }
                }
            }
            nodes.push(node);
        }
        self.nodes = nodes;
        self.entry = renumbered[self.entry];
        self.changed = true;
        gone
    }

    /// Whether the graph points only at itself: every way out of a block
    /// leads to a block, and the entry is one.
    pub fn validate(&self) -> Result<(), String> {
        let count = self.nodes.len();
        if self.entry >= count {
            return Err(format!("the entry at block {} of {count}", self.entry));
        }
        for (index, node) in self.nodes.iter().enumerate() {
            for target in node.terminator.successors() {
                if target >= count {
                    return Err(format!(
                        "block {index} leading to block {target}, of {count}"
                    ));
                }
            }
            if let Some(other) = self.nodes[..index]
                .iter()
                .position(|earlier| earlier.address == node.address)
            {
                return Err(format!(
                    "blocks {other} and {index} both at {:#x}, the address that labels a block",
                    node.address
                ));
            }
        }
        Ok(())
    }

    /// The graph as JSON for a rewriter that is a command: the blocks with
    /// their statements as text and their terminators.
    pub fn to_json(&self) -> serde_json::Value {
        let text = |node: &AstNode| {
            crate::emit::emit_node(node)
                .trim_end()
                .trim_end_matches(';')
                .to_string()
        };
        serde_json::json!({
            "function": self.function,
            "function_hex": format!("{:#x}", self.function),
            "name": self.name,
            "entry": self.entry,
            "blocks": self.nodes.iter().enumerate().map(|(id, node)| serde_json::json!({
                "id": id,
                "address": node.address,
                "address_hex": format!("{:#x}", node.address),
                "statements": node.statements.iter().enumerate().map(|(index, statement)| serde_json::json!({
                    "index": index,
                    "text": text(&statement.node),
                    "addresses": statement.addresses,
                })).collect::<Vec<_>>(),
                "terminator": match &node.terminator {
                    Terminator::Return => serde_json::json!({ "kind": "return" }),
                    Terminator::Goto { target, .. } => serde_json::json!({ "kind": "goto", "target": target }),
                    Terminator::Branch { cond, taken, next, .. } => serde_json::json!({
                        "kind": "branch", "cond": text(cond), "taken": taken, "next": next,
                    }),
                    Terminator::Switch { index, cases, .. } => serde_json::json!({
                        "kind": "switch", "index": text(index),
                        "cases": cases.iter().map(|(values, target)| serde_json::json!({
                            "values": values, "target": target,
                        })).collect::<Vec<_>>(),
                    }),
                },
            })).collect::<Vec<_>>(),
        })
    }

    /// Apply a command's edits, in order, each naming blocks and statements
    /// as they stand when it is applied: `remove`, `copy`, `move`,
    /// `add_block`, `redirect`, `goto`, `return`, `branch` (a block's
    /// condition reused with new targets), `switch_case` (one case of a
    /// block's switch pointed elsewhere), `prune` (the blocks the entry no
    /// longer reaches dropped, the rest renumbered).
    pub fn apply_edits(&mut self, edits: &serde_json::Value) -> Result<(), String> {
        let edits = match edits {
            serde_json::Value::Null => return Ok(()),
            serde_json::Value::Object(answer) => match answer.get("edits") {
                None | Some(serde_json::Value::Null) => return Ok(()),
                Some(serde_json::Value::Array(edits)) => edits.clone(),
                Some(_) => return Err("the edits are a JSON array".to_string()),
            },
            serde_json::Value::Array(edits) => edits.clone(),
            _ => return Err("the answer is a JSON object with the edits".to_string()),
        };
        for (at, edit) in edits.iter().enumerate() {
            let object = edit
                .as_object()
                .ok_or_else(|| format!("edit {at} is a JSON object"))?;
            let op = object
                .get("op")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("edit {at} names its op"))?;
            let index = |key: &str| -> Result<usize, String> {
                object
                    .get(key)
                    .and_then(number)
                    .map(|value| value as usize)
                    .ok_or_else(|| format!("edit {at} ({op}) gives {key:?} as a number"))
            };
            let optional = |key: &str| -> Result<Option<usize>, String> {
                match object.get(key) {
                    None | Some(serde_json::Value::Null) => Ok(None),
                    Some(value) => number(value)
                        .map(|value| Some(value as usize))
                        .ok_or_else(|| format!("edit {at} ({op}) gives {key:?} as a number")),
                }
            };
            let result = match op {
                "remove" => self
                    .remove_statement(index("block")?, index("statement")?)
                    .map(|_| ()),
                "copy" | "move" => {
                    let (from, statement) = (index("from")?, index("statement")?);
                    let to = index("to")?;
                    let copied = if op == "copy" {
                        self.copy_statement(from, statement)?
                    } else {
                        self.remove_statement(from, statement)?
                    };
                    let at = optional("at")?.unwrap_or(usize::MAX);
                    self.insert_statement(to, at, copied)
                }
                "add_block" => {
                    let address = optional("address")?
                        .map(|address| address as u64)
                        .unwrap_or_else(|| self.fresh_address());
                    let mut statements = Vec::new();
                    for (which, source) in object
                        .get("statements")
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                        .enumerate()
                    {
                        let from = source.get("from").and_then(number).ok_or_else(|| {
                            format!("edit {at} ({op}): statement {which} names the block it is copied from")
                        })?;
                        let statement = source.get("statement").and_then(number).ok_or_else(|| {
                            format!("edit {at} ({op}): statement {which} names the statement it copies")
                        })?;
                        statements.push(self.copy_statement(from as usize, statement as usize)?);
                    }
                    let terminator = match object.get("terminator") {
                        None | Some(serde_json::Value::Null) => {
                            return Err(format!(
                                "edit {at} (add_block): a new block names its terminator"
                            ))
                        }
                        Some(given) => self.terminator_of(given, at)?,
                    };
                    self.add_block(address, statements, terminator).map(|_| ())
                }
                "redirect" => self.redirect(index("block")?, index("from")?, index("to")?),
                "prune" => {
                    self.prune_unreachable();
                    Ok(())
                }
                "goto" => self.set_goto(index("block")?, index("target")?),
                "return" => self.set_return(index("block")?),
                "branch" => {
                    let block = index("block")?;
                    let (cond, taken, next) = self.branch_of(object, at)?;
                    self.set_branch(block, cond, taken, next)
                }
                "switch_case" => {
                    let (block, from, to) = (index("block")?, index("from")?, index("to")?);
                    let count = self.nodes.len();
                    if to >= count {
                        Err(format!("no block {to}: there are {count}"))
                    } else {
                        let node = self.node_mut(block)?;
                        match &mut node.terminator {
                            Terminator::Switch { cases, .. } => {
                                let mut hit = false;
                                for (_, target) in cases.iter_mut() {
                                    if *target == from {
                                        *target = to;
                                        hit = true;
                                    }
                                }
                                if hit {
                                    self.changed = true;
                                    Ok(())
                                } else {
                                    Err(format!(
                                        "block {block}'s switch has no case to block {from}"
                                    ))
                                }
                            }
                            _ => Err(format!("block {block} does not switch")),
                        }
                    }
                }
                other => Err(format!("no such op: {other:?}")),
            };
            result.map_err(|error| format!("edit {at} ({op}): {error}"))?;
        }
        Ok(())
    }

    /// A terminator a command describes for a new block: `return`, `goto`
    /// with a `target`, or `branch` as [`Rewrite::branch_of`] reads it.
    fn terminator_of(&self, given: &serde_json::Value, at: usize) -> Result<Terminator, String> {
        let object = given
            .as_object()
            .ok_or_else(|| format!("edit {at}: the terminator is a JSON object"))?;
        match object.get("kind").and_then(serde_json::Value::as_str) {
            Some("return") => Ok(Terminator::Return),
            None => Err(format!("edit {at}: a terminator names its kind")),
            Some("goto") => {
                let target = object
                    .get("target")
                    .and_then(number)
                    .ok_or_else(|| format!("edit {at}: a goto names its target"))?;
                Ok(Terminator::Goto {
                    target: target as usize,
                    addresses: Vec::new(),
                })
            }
            Some("branch") => {
                let (cond, taken, next) = self.branch_of(object, at)?;
                Ok(Terminator::Branch {
                    cond,
                    taken,
                    next,
                    addresses: Vec::new(),
                })
            }
            Some(other) => Err(format!(
                "edit {at}: a terminator is return, goto or branch, not {other:?}"
            )),
        }
    }

    /// A branch a command describes: the condition of the block `cond_of`
    /// — a command cannot write expressions, only reuse them — and the
    /// `taken` and `next` blocks.
    fn branch_of(
        &self,
        object: &serde_json::Map<String, serde_json::Value>,
        at: usize,
    ) -> Result<(AstNode, usize, usize), String> {
        let source = object.get("cond_of").and_then(number).ok_or_else(|| {
            format!("edit {at}: a branch names cond_of, the block whose condition it tests")
        })? as usize;
        let cond = match self.nodes.get(source).map(|node| &node.terminator) {
            Some(Terminator::Branch { cond, .. }) => cond.clone(),
            Some(_) => return Err(format!("edit {at}: block {source} does not branch")),
            None => return Err(format!("edit {at}: no block {source}")),
        };
        let taken = object
            .get("taken")
            .and_then(number)
            .ok_or_else(|| format!("edit {at}: a branch names taken"))?
            as usize;
        let next = object
            .get("next")
            .and_then(number)
            .ok_or_else(|| format!("edit {at}: a branch names next"))? as usize;
        Ok((cond, taken, next))
    }
}

/// The addresses a terminator came from, kept when it is replaced so the
/// new one still maps onto the listing.
fn terminator_addresses(terminator: &Terminator) -> Vec<u64> {
    match terminator {
        Terminator::Return => Vec::new(),
        Terminator::Goto { addresses, .. }
        | Terminator::Branch { addresses, .. }
        | Terminator::Switch { addresses, .. } => addresses.clone(),
    }
}

/// A rewriter that is a command: given the graph as JSON on its standard
/// input, it prints the edits to apply as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalRewriter {
    pub name: String,
    pub command: Vec<String>,
    pub timeout: Duration,
    /// The functions the command is run for, by name or address; every
    /// function when empty.
    pub functions: Vec<String>,
}

impl Rewriter for ExternalRewriter {
    fn name(&self) -> &str {
        &self.name
    }

    fn wants(&self, address: u64, name: &str) -> bool {
        self.functions.is_empty()
            || self.functions.iter().any(|wanted| {
                wanted == name
                    || wanted
                        .strip_prefix("0x")
                        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                        .is_some_and(|wanted| wanted == address)
                    || wanted.parse::<u64>().is_ok_and(|wanted| wanted == address)
            })
    }

    fn rewrite(&self, rewrite: &mut Rewrite) -> Result<(), String> {
        let input = serde_json::to_vec(&rewrite.to_json()).map_err(|error| error.to_string())?;
        let output = run_command(&self.command, &input, self.timeout)?;
        if output.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let edits: serde_json::Value = serde_json::from_slice(&output)
            .map_err(|error| format!("the answer is not JSON: {error}"))?;
        rewrite.apply_edits(&edits)
    }
}

/// Everything registered in this process.
#[derive(Default)]
struct Registry {
    loaders: Vec<Arc<dyn Loader>>,
    architectures: Vec<Arc<dyn Architecture>>,
    rewriters: Vec<Arc<dyn Rewriter>>,
}

fn registry() -> &'static RwLock<Registry> {
    static REGISTRY: std::sync::OnceLock<RwLock<Registry>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(Registry::default()))
}

/// Add a loader: every image opened after is offered to it first. One of
/// the same name is replaced, and takes its turn at the end.
pub fn register_loader(loader: Arc<dyn Loader>) {
    let mut registry = registry().write().unwrap_or_else(PoisonError::into_inner);
    let name = loader.name().to_string();
    registry.loaders.retain(|known| known.name() != name);
    registry.loaders.push(loader);
}

/// Add an architecture: every image of one of its languages opened after
/// is decoded by it. One of the same name is replaced.
pub fn register_architecture(architecture: Arc<dyn Architecture>) {
    let mut registry = registry().write().unwrap_or_else(PoisonError::into_inner);
    let name = architecture.name().to_string();
    registry.architectures.retain(|known| known.name() != name);
    registry.architectures.push(architecture);
}

/// Add a rewriter: every function lifted after passes through it, after
/// the ones registered before. One of the same name is replaced.
pub fn register_rewriter(rewriter: Arc<dyn Rewriter>) {
    let mut registry = registry().write().unwrap_or_else(PoisonError::into_inner);
    let name = rewriter.name().to_string();
    registry.rewriters.retain(|known| known.name() != name);
    registry.rewriters.push(rewriter);
}

/// The rewriters registered, in the order they run.
pub fn rewriters() -> Vec<Arc<dyn Rewriter>> {
    registry()
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .rewriters
        .clone()
}

/// Run every registered rewriter that wants the function over its
/// medium-level graph, in order: the nodes as they stand after, and whether
/// any rewriter ran. A rewriter's failure, or a graph it leaves pointing
/// outside itself or with two blocks at one address, refuses the lift with
/// the rewriter's name.
pub(crate) fn rewrite_nodes(
    function: u64,
    name: &str,
    entry: usize,
    nodes: Vec<Node>,
) -> Result<(Vec<Node>, bool), NotLifted> {
    let rewriters = rewriters();
    if rewriters.is_empty() {
        return Ok((nodes, false));
    }
    let mut rewrite = Rewrite {
        function,
        name: name.to_string(),
        entry,
        nodes,
        changed: false,
    };
    let mut ran = false;
    for rewriter in rewriters {
        if !rewriter.wants(function, name) {
            continue;
        }
        ran = true;
        rewriter.rewrite(&mut rewrite).map_err(|error| {
            NotLifted::new(format!("the rewriter {}: {error}", rewriter.name()))
        })?;
        rewrite.validate().map_err(|error| {
            NotLifted::new(format!("the rewriter {} left {error}", rewriter.name()))
        })?;
    }
    // Analyzed again whenever one ran: a rewriter may edit the nodes
    // directly without marking them changed.
    Ok((rewrite.nodes, ran))
}

/// The loaders registered, in the order they were.
pub fn loaders() -> Vec<Arc<dyn Loader>> {
    registry()
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .loaders
        .clone()
}

/// The architectures registered, in the order they were.
pub fn architectures() -> Vec<Arc<dyn Architecture>> {
    registry()
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .architectures
        .clone()
}

/// The first registered loader that recognizes `bytes`.
pub fn loader_for(bytes: &[u8]) -> Option<Arc<dyn Loader>> {
    loaders()
        .into_iter()
        .find(|loader| loader.recognizes(bytes))
}

/// The registered architecture that decodes `language`, when one does.
pub fn architecture_for(language: &str) -> Option<Arc<dyn Architecture>> {
    architectures().into_iter().find(|architecture| {
        architecture
            .languages()
            .iter()
            .any(|known| known == language)
    })
}

// ---- External plugins: commands declared in a manifest. ----

/// How long a command is given unless its manifest says otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// The longest a command's answer is read, in bytes.
const LONGEST_ANSWER: usize = 256 << 20;
/// The environment variable that names more plugin directories, separated
/// as the platform separates paths.
pub const PLUGIN_DIRS_VARIABLE: &str = "AG_PLUGINS";

/// A loader that is a command: given the file's bytes on its standard
/// input, it prints the image as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLoader {
    pub name: String,
    /// The bytes a file of the format starts with.
    pub magic: Vec<u8>,
    /// The command and its arguments, paths resolved.
    pub command: Vec<String>,
    /// How long the command is given.
    pub timeout: Duration,
}

/// An architecture that is a command: given a section as JSON on its
/// standard input, it prints the instructions as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalArchitecture {
    pub name: String,
    pub languages: Vec<String>,
    pub bitness: Bitness,
    pub command: Vec<String>,
    pub timeout: Duration,
    /// The command that recovers a function's blocks, when the manifest
    /// gives one.
    pub blocks: Option<Vec<String>>,
    /// The command that lifts a whole function, when the manifest gives one.
    pub lift: Option<Vec<String>>,
}

impl ExternalArchitecture {
    /// Run one of the architecture's commands with a JSON request; its JSON
    /// answer.
    fn ask(
        &self,
        command: &[String],
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let input = serde_json::to_vec(request).map_err(|error| error.to_string())?;
        let output = run_command(command, &input, self.timeout)?;
        serde_json::from_slice(&output)
            .map_err(|error| format!("{}: the answer is not JSON: {error}", self.name))
    }
}

/// The instructions of a section as JSON for a command: each its address,
/// its length, its flow by name and the target the flow names.
fn instructions_json(disasm: &Disasm) -> Vec<serde_json::Value> {
    disasm
        .instructions
        .iter()
        .map(|instruction| {
            let (flow, target) = flow_name(&instruction.flow);
            let mut row = serde_json::json!({
                "address": instruction.address,
                "address_hex": format!("{:#x}", instruction.address),
                "length": instruction.length,
                "flow": flow,
            });
            if let Some(target) = target {
                row["target"] = serde_json::json!(target);
                row["target_hex"] = serde_json::json!(format!("{target:#x}"));
            }
            row
        })
        .collect()
}

/// A flow by the name the architecture conversation spells it, and the
/// target it names.
fn flow_name(flow: &Flow) -> (&'static str, Option<u64>) {
    match flow {
        Flow::Next => ("next", None),
        Flow::UnconditionalBranch(target) => ("jump", Some(*target)),
        Flow::ConditionalBranch(target) => ("branch", Some(*target)),
        Flow::IndirectBranch => ("indirect-jump", None),
        Flow::Call(target) => ("call", Some(*target)),
        Flow::IndirectCall => ("indirect-call", None),
        Flow::Return => ("return", None),
        Flow::Halt => ("halt", None),
        Flow::Trap => ("trap", None),
        Flow::Interrupt => ("interrupt", None),
        Flow::Syscall => ("syscall", None),
        Flow::Invalid => ("invalid", None),
        _ => ("next", None),
    }
}

/// Bytes as lower-case hex, two digits each.
fn hex_text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The numbers in a JSON list, each a number or hex text; none for
/// anything else.
fn numbers(value: Option<&serde_json::Value>) -> Vec<u64> {
    value
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(number)
        .collect()
}

/// A lifted function as a command answers it: its `return_type`, `params`
/// and `locals` (each a `name` and a `type`), its `entry`, its `frame`,
/// and its `blocks` — each an `address`, its `statements` (each the
/// `addresses` it came from and an `expr`, an expression tree as
/// [`expression`] reads it) and a `terminator` (`return`; `goto` with a
/// `target`; `branch` with a `cond` tree, `taken` and `next`; `switch`
/// with an `index` tree and `cases` of `values` and a `target`).
pub fn graph_of(answer: &serde_json::Value) -> Result<LiftedGraph, String> {
    let object = answer
        .as_object()
        .ok_or("the lifted function is a JSON object")?;
    let variables = |key: &str| -> Result<Vec<Variable>, String> {
        object
            .get(key)
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .map(|row| {
                let name = row
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| format!("a variable of {key} has a name"))?;
                let ty = row
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("long");
                Ok(Variable {
                    ty: ty.to_string(),
                    name: name.to_string(),
                })
            })
            .collect()
    };
    let blocks = object
        .get("blocks")
        .and_then(serde_json::Value::as_array)
        .ok_or("the lifted function lists `blocks`")?;
    let mut nodes = Vec::with_capacity(blocks.len());
    for (index, block) in blocks.iter().enumerate() {
        let address = block
            .get("address")
            .and_then(number)
            .ok_or_else(|| format!("block {index} has an address"))?;
        let mut statements = Vec::new();
        for (at, row) in block
            .get("statements")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let expr = row
                .get("expr")
                .ok_or_else(|| format!("statement {at} of block {index} has an `expr`"))?;
            statements.push(Statement {
                node: expression(expr)
                    .map_err(|error| format!("statement {at} of block {index}: {error}"))?,
                addresses: numbers(row.get("addresses")),
                kind: StatementKind::Plain,
            });
        }
        let terminator = block
            .get("terminator")
            .ok_or_else(|| format!("block {index} has a terminator"))?;
        let kind = terminator
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("block {index}'s terminator names its kind"))?;
        let addresses = numbers(terminator.get("addresses"));
        let target_of = |key: &str| -> Result<usize, String> {
            terminator
                .get(key)
                .and_then(number)
                .map(|target| target as usize)
                .ok_or_else(|| format!("block {index}'s {kind} names `{key}`"))
        };
        let terminator = match kind {
            "return" => Terminator::Return,
            "goto" => Terminator::Goto {
                target: target_of("target")?,
                addresses,
            },
            "branch" => Terminator::Branch {
                cond: expression(
                    terminator
                        .get("cond")
                        .ok_or_else(|| format!("block {index}'s branch has a `cond`"))?,
                )
                .map_err(|error| format!("block {index}'s branch: {error}"))?,
                taken: target_of("taken")?,
                next: target_of("next")?,
                addresses,
            },
            "switch" => Terminator::Switch {
                index: expression(
                    terminator
                        .get("index")
                        .ok_or_else(|| format!("block {index}'s switch has an `index`"))?,
                )
                .map_err(|error| format!("block {index}'s switch: {error}"))?,
                cases: terminator
                    .get("cases")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|case| {
                        let values: Vec<i64> = case
                            .get("values")
                            .and_then(serde_json::Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(|value| {
                                value.as_i64().or_else(|| number(value).map(|v| v as i64))
                            })
                            .collect();
                        let target = case.get("target").and_then(number).ok_or_else(|| {
                            format!("a case of block {index}'s switch names its target")
                        })?;
                        Ok((values, target as usize))
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                addresses,
            },
            other => {
                return Err(format!(
                    "block {index}'s terminator is return, goto, branch or switch, not {other:?}"
                ))
            }
        };
        nodes.push(Node {
            address,
            statements,
            terminator,
        });
    }
    let graph = LiftedGraph {
        return_type: object
            .get("return_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("void")
            .to_string(),
        params: variables("params")?,
        locals: variables("locals")?,
        entry: object
            .get("entry")
            .and_then(number)
            .map_or(0, |entry| entry as usize),
        nodes,
        frame: numbers(object.get("frame")),
    };
    Rewrite::new(0, "", graph.entry, graph.nodes.clone())
        .validate()
        .map_err(|error| format!("the lifted function has {error}"))?;
    Ok(graph)
}

/// An expression as a command spells it, as a tree: a number is a constant
/// (8 bytes wide), a string a variable, `true` and `false` a condition
/// that always holds or never does; an object is one of `{"const": n,
/// "width": bytes}`, `{"var": name}`, `{"string": text}`, `{"binary": op,
/// "lhs": …, "rhs": …}` with the operator spelled as C (`+ - * / % & | ^
/// << >> == != < <= > >= && ||`), `{"assign": lhs, "rhs": …}`, `{"deref":
/// …}`, `{"address_of": …}`, `{"call": name or tree, "args": […],
/// "address": n}`, `{"return": … or null}`, `{"cast": type, "target": …}`
/// or `{"intrinsic": name, "args": […]}`.
pub fn expression(value: &serde_json::Value) -> Result<AstNode, String> {
    use crate::ast::BinaryOp;
    match value {
        serde_json::Value::Number(_) => number(value)
            .map(|value| AstNode::constant(value, 8))
            .ok_or_else(|| "a constant is a whole number".to_string()),
        serde_json::Value::String(name) => Ok(AstNode::var(name.clone())),
        serde_json::Value::Bool(true) => Ok(AstNode::ConditionTrue),
        serde_json::Value::Bool(false) => Ok(AstNode::ConditionFalse),
        serde_json::Value::Object(object) => {
            let sub = |key: &str| -> Result<AstNode, String> {
                object
                    .get(key)
                    .ok_or_else(|| format!("`{key}` is missing"))
                    .and_then(expression)
            };
            let args = || -> Result<Vec<AstNode>, String> {
                object
                    .get("args")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(expression)
                    .collect()
            };
            if let Some(constant) = object.get("const") {
                let width = object
                    .get("width")
                    .and_then(number)
                    .map_or(8, |width| width as u32);
                return number(constant)
                    .or_else(|| constant.as_i64().map(|v| v as u64))
                    .map(|value| AstNode::constant(value, width))
                    .ok_or_else(|| "a constant is a whole number".to_string());
            }
            if let Some(name) = object.get("var").and_then(serde_json::Value::as_str) {
                return Ok(AstNode::var(name));
            }
            if let Some(text) = object.get("string").and_then(serde_json::Value::as_str) {
                return Ok(AstNode::StringLiteral {
                    text: text.to_string(),
                });
            }
            if let Some(op) = object.get("binary").and_then(serde_json::Value::as_str) {
                let op = match op {
                    "+" => BinaryOp::Add,
                    "-" => BinaryOp::Sub,
                    "*" => BinaryOp::Mul,
                    "/" => BinaryOp::Div,
                    "%" => BinaryOp::Mod,
                    "&" => BinaryOp::And,
                    "|" => BinaryOp::Or,
                    "^" => BinaryOp::Xor,
                    "<<" => BinaryOp::Shl,
                    ">>" => BinaryOp::Shr,
                    "==" => BinaryOp::Equal,
                    "!=" => BinaryOp::NotEqual,
                    "<" => BinaryOp::Less,
                    "<=" => BinaryOp::LessEqual,
                    ">" => BinaryOp::Greater,
                    ">=" => BinaryOp::GreaterEqual,
                    "&&" => BinaryOp::LogicalAnd,
                    "||" => BinaryOp::LogicalOr,
                    other => return Err(format!("no such operator: {other:?}")),
                };
                return Ok(AstNode::binary(sub("lhs")?, op, sub("rhs")?));
            }
            if object.contains_key("assign") {
                return Ok(AstNode::Assign {
                    lhs: Box::new(sub("assign")?),
                    rhs: Box::new(sub("rhs")?),
                });
            }
            if object.contains_key("deref") {
                return Ok(AstNode::Deref {
                    target: Box::new(sub("deref")?),
                });
            }
            if object.contains_key("address_of") {
                return Ok(AstNode::AddressOf {
                    target: Box::new(sub("address_of")?),
                });
            }
            if let Some(callee) = object.get("call") {
                let callee = match callee {
                    serde_json::Value::String(name) => AstNode::FunctionName {
                        name: name.clone(),
                        address: object.get("address").and_then(number).unwrap_or(0),
                    },
                    other => expression(other)?,
                };
                return Ok(AstNode::Call {
                    callee: Box::new(callee),
                    args: args()?,
                });
            }
            if object.contains_key("return") {
                let value = match object.get("return") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(value) => Some(Box::new(expression(value)?)),
                };
                return Ok(AstNode::Return { value });
            }
            if let Some(ty) = object.get("cast").and_then(serde_json::Value::as_str) {
                return Ok(AstNode::Cast {
                    ty: ty.to_string(),
                    target: Box::new(sub("target")?),
                });
            }
            if let Some(name) = object.get("intrinsic").and_then(serde_json::Value::as_str) {
                return Ok(AstNode::Intrinsic {
                    name: name.to_string(),
                    args: args()?,
                });
            }
            Err(format!(
                "an expression is a const, var, string, binary, assign, deref, address_of, call, return, cast or intrinsic, not {}",
                object.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
        }
        other => Err(format!(
            "an expression is a number, a string, a boolean or an object, not {other}"
        )),
    }
}

/// A tool that is a command, as a manifest declares it; `ag_image::plugin`
/// runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalTool {
    pub name: String,
    pub description: String,
    pub command: Vec<String>,
    pub timeout: Duration,
    /// The JSON Schema of the tool's arguments, when the manifest gives one.
    pub input_schema: Option<serde_json::Value>,
}

/// One manifest: a JSON file declaring loaders, architectures and tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Where the manifest was read from.
    pub path: PathBuf,
    /// The plugin's name: the manifest's `name`, or the file's stem.
    pub name: String,
    pub loaders: Vec<ExternalLoader>,
    pub architectures: Vec<ExternalArchitecture>,
    pub tools: Vec<ExternalTool>,
    pub rewriters: Vec<ExternalRewriter>,
}

/// The directories manifests are read from: the ones `AG_PLUGINS` names,
/// then `$XDG_CONFIG_HOME/ag/plugins` or `~/.config/ag/plugins`.
pub fn manifest_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(listed) = std::env::var_os(PLUGIN_DIRS_VARIABLE) {
        dirs.extend(std::env::split_paths(&listed).filter(|dir| !dir.as_os_str().is_empty()));
    }
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            ["HOME", "USERPROFILE"]
                .iter()
                .find_map(|key| std::env::var_os(key).filter(|value| !value.is_empty()))
                .map(|home| PathBuf::from(home).join(".config"))
        });
    if let Some(config) = config {
        dirs.push(config.join("ag").join("plugins"));
    }
    dirs
}

/// A number in a manifest or an answer: a JSON number, or hex text such
/// as `0x1000`.
pub fn number(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => {
            let text = text.trim();
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                hex.chars()
                    .all(|c| c.is_ascii_hexdigit())
                    .then(|| u64::from_str_radix(hex, 16).ok())
                    .flatten()
            } else {
                text.chars()
                    .all(|c| c.is_ascii_digit())
                    .then(|| text.parse().ok())
                    .flatten()
            }
        }
        _ => None,
    }
}

fn strings(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The bytes hex text spells, spaces allowed between pairs.
fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || !digits.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).ok())
        .collect()
}

/// A command as the manifest spells it, its program found: `${dir}` in any
/// element is the manifest's directory, and a program that names a path —
/// one with a separator in it — is taken from the manifest's directory
/// when it is relative. A bare program name is found on `PATH`, as a shell
/// finds it; the arguments are passed as they are.
fn resolve_command(command: &[String], dir: &Path) -> Vec<String> {
    command
        .iter()
        .enumerate()
        .map(|(index, element)| {
            let element = element.replace("${dir}", &dir.display().to_string());
            let names_path = element.contains('/') || element.contains('\\');
            if index == 0 && names_path && Path::new(&element).is_relative() {
                dir.join(&element).display().to_string()
            } else {
                element
            }
        })
        .collect()
}

/// Read one manifest.
pub fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("{error}"))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("not JSON: {error}"))?;
    let object = json
        .as_object()
        .ok_or_else(|| "a manifest is a JSON object".to_string())?;
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            path.file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let entry_name = |entry: &serde_json::Map<String, serde_json::Value>, index: usize| match entry
        .get("name")
        .and_then(serde_json::Value::as_str)
    {
        Some(given) => given.to_string(),
        None if index == 0 => name.clone(),
        None => format!("{name}-{index}"),
    };
    let command_of = |entry: &serde_json::Map<String, serde_json::Value>,
                      what: &str|
     -> Result<Vec<String>, String> {
        let command = strings(entry.get("command"));
        if command.is_empty() {
            return Err(format!(
                "the {what} {:?} names no command",
                entry.get("name")
            ));
        }
        Ok(resolve_command(&command, &dir))
    };
    let timeout_of =
        |entry: &serde_json::Map<String, serde_json::Value>| -> Result<Duration, String> {
            match entry.get("timeout") {
                None | Some(serde_json::Value::Null) => Ok(DEFAULT_TIMEOUT),
                Some(value) => number(value)
                    .filter(|seconds| *seconds >= 1)
                    .map(Duration::from_secs)
                    .ok_or_else(|| "a timeout is a number of seconds from 1".to_string()),
            }
        };
    let entries = |key: &str| -> Result<Vec<serde_json::Map<String, serde_json::Value>>, String> {
        object
            .get(key)
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .map(|entry| {
                entry
                    .as_object()
                    .cloned()
                    .ok_or_else(|| format!("an entry of {key:?} is a JSON object"))
            })
            .collect()
    };
    let mut loaders = Vec::new();
    for (index, entry) in entries("loaders")?.iter().enumerate() {
        let magic = entry
            .get("magic")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                "a loader names its magic: the hex of the bytes a file starts with".to_string()
            })?;
        let magic = hex_bytes(magic).ok_or_else(|| {
            format!("the magic {magic:?} is not hex, in pairs, of at least one byte")
        })?;
        loaders.push(ExternalLoader {
            name: entry_name(entry, index),
            magic,
            command: command_of(entry, "loader")?,
            timeout: timeout_of(entry)?,
        });
    }
    let mut architectures = Vec::new();
    for (index, entry) in entries("architectures")?.iter().enumerate() {
        let languages = strings(entry.get("languages"));
        if languages.is_empty() {
            return Err("an architecture names the languages it decodes".to_string());
        }
        let bitness = match entry.get("bitness") {
            None | Some(serde_json::Value::Null) => Bitness::Bits64,
            Some(value) => match number(value) {
                Some(16) => Bitness::Bits16,
                Some(32) => Bitness::Bits32,
                Some(64) => Bitness::Bits64,
                _ => return Err(format!("a bitness of {value} is not 16, 32 or 64")),
            },
        };
        let optional_command = |key: &str| -> Option<Vec<String>> {
            let command = strings(entry.get(key));
            (!command.is_empty()).then(|| resolve_command(&command, &dir))
        };
        architectures.push(ExternalArchitecture {
            name: entry_name(entry, index),
            languages,
            bitness,
            command: command_of(entry, "architecture")?,
            timeout: timeout_of(entry)?,
            blocks: optional_command("blocks"),
            lift: optional_command("lift"),
        });
    }
    let mut tools = Vec::new();
    for entry in entries("tools")? {
        let tool_name = entry
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "a tool has a name".to_string())?;
        if tool_name.is_empty()
            || !tool_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "the tool name {tool_name:?} is letters, digits, _ and - only, and not empty"
            ));
        }
        let input_schema = match entry.get("inputSchema") {
            None | Some(serde_json::Value::Null) => None,
            Some(schema) if schema.is_object() => Some(schema.clone()),
            Some(_) => return Err(format!("the inputSchema of {tool_name} is a JSON object")),
        };
        tools.push(ExternalTool {
            name: tool_name.to_string(),
            description: entry
                .get("description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("A tool of a plugin.")
                .to_string(),
            command: command_of(&entry, "tool")?,
            timeout: timeout_of(&entry)?,
            input_schema,
        });
    }
    let mut rewriters = Vec::new();
    for (index, entry) in entries("rewriters")?.iter().enumerate() {
        rewriters.push(ExternalRewriter {
            name: entry_name(entry, index),
            command: command_of(entry, "rewriter")?,
            timeout: timeout_of(entry)?,
            functions: strings(entry.get("functions")),
        });
    }
    Ok(Manifest {
        path: path.to_path_buf(),
        name,
        loaders,
        architectures,
        tools,
        rewriters,
    })
}

/// Read every manifest in `dirs` (the `.json` files, in name order), and
/// register the loaders and architectures they declare. The manifests come
/// back so the tools can be registered where the image is, and so the
/// plugins can be listed; a manifest that does not read, or a name two
/// manifests both use, is reported — the later one replaces the earlier.
pub fn load_manifests(dirs: &[PathBuf]) -> (Vec<Manifest>, Vec<String>) {
    let mut manifests: Vec<Manifest> = Vec::new();
    let mut problems = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect();
        paths.sort();
        for path in paths {
            match read_manifest(&path) {
                Ok(manifest) => {
                    for loader in &manifest.loaders {
                        if manifests
                            .iter()
                            .any(|known| known.loaders.iter().any(|l| l.name == loader.name))
                        {
                            problems.push(format!(
                                "{}: the loader {:?} is declared again, and replaces the first",
                                path.display(),
                                loader.name
                            ));
                        }
                        register_loader(Arc::new(loader.clone()));
                    }
                    for architecture in &manifest.architectures {
                        if manifests.iter().any(|known| {
                            known
                                .architectures
                                .iter()
                                .any(|a| a.name == architecture.name)
                        }) {
                            problems.push(format!(
                                "{}: the architecture {:?} is declared again, and replaces the first",
                                path.display(),
                                architecture.name
                            ));
                        }
                        register_architecture(Arc::new(architecture.clone()));
                    }
                    for tool in &manifest.tools {
                        if manifests
                            .iter()
                            .any(|known| known.tools.iter().any(|t| t.name == tool.name))
                        {
                            problems.push(format!(
                                "{}: the tool {:?} is declared again, and replaces the first",
                                path.display(),
                                tool.name
                            ));
                        }
                    }
                    for rewriter in &manifest.rewriters {
                        if manifests
                            .iter()
                            .any(|known| known.rewriters.iter().any(|r| r.name == rewriter.name))
                        {
                            problems.push(format!(
                                "{}: the rewriter {:?} is declared again, and replaces the first",
                                path.display(),
                                rewriter.name
                            ));
                        }
                        register_rewriter(Arc::new(rewriter.clone()));
                    }
                    manifests.push(manifest);
                }
                Err(error) => problems.push(format!("{}: {error}", path.display())),
            }
        }
    }
    (manifests, problems)
}

/// Run a command with `input` on its standard input; its standard output,
/// when it ends well within `timeout`. A command that goes on past the
/// time, or answers with more than the server reads, is ended.
pub fn run_command(command: &[String], input: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| "no command".to_string())?;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("starting {program}: {error}"))?;
    let deadline = Instant::now() + timeout;
    // The command's own words go to this process's standard error, through
    // a thread of their own: a pipe rather than the terminal itself, so a
    // child the command leaves behind holds nothing of ours open.
    if let Some(mut stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut stderr, &mut std::io::stderr());
        });
    }
    // The input is written on a thread, so a command that answers before it
    // has read everything does not stall the write; the output is read on
    // another, so the wait can end at the deadline.
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "no input pipe".to_string())?;
    let input = input.to_vec();
    std::thread::spawn(move || {
        // A command that reads no more closes its end; that is its choice.
        let _ = stdin.write_all(&input);
    });
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "no output pipe".to_string())?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let read = stdout
            .by_ref()
            .take(LONGEST_ANSWER as u64 + 1)
            .read_to_end(&mut out);
        let _ = sender.send(read.map(|_| out));
    });
    let output = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(left.min(Duration::from_millis(100))) {
            Ok(Ok(output)) => break output,
            Ok(Err(error)) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("reading {program}'s answer: {error}"));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program}'s answer was lost"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{program} did not answer within {} seconds",
                        timeout.as_secs()
                    ));
                }
            }
        }
    };
    if output.len() > LONGEST_ANSWER {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "{program} answered with more than {LONGEST_ANSWER} bytes"
        ));
    }
    // The output has closed; the command ends, or is ended at the deadline.
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{program} did not end within {} seconds",
                    timeout.as_secs()
                ));
            }
            Err(error) => return Err(format!("waiting for {program}: {error}")),
        }
    };
    if !status.success() {
        return Err(format!("{program} ended with {status}"));
    }
    Ok(output)
}

fn answer_json(
    command: &[String],
    input: &[u8],
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    let output = run_command(command, input, timeout)?;
    serde_json::from_slice(&output).map_err(|error| {
        format!(
            "{} did not answer with JSON: {error}",
            command.first().map(String::as_str).unwrap_or("the command")
        )
    })
}

impl Loader for ExternalLoader {
    fn name(&self) -> &str {
        &self.name
    }

    fn recognizes(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(&self.magic)
    }

    fn load(&self, name: &str, bytes: &[u8]) -> Result<LoadedImage, String> {
        let answer = answer_json(&self.command, bytes, self.timeout)?;
        let object = answer
            .as_object()
            .ok_or_else(|| format!("{name}: the loader's answer is a JSON object"))?;
        let language = object
            .get("language")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{name}: the loader's answer names a language"))?
            .to_string();
        let rows = |key: &str| -> Vec<&serde_json::Map<String, serde_json::Value>> {
            object
                .get(key)
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_object)
                .collect()
        };
        let text = |row: &serde_json::Map<String, serde_json::Value>, key: &str| -> String {
            row.get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let sections = rows("sections")
            .into_iter()
            .map(|row| {
                let vma = row
                    .get("vma")
                    .or_else(|| row.get("address"))
                    .and_then(number);
                let size = row.get("size").and_then(number);
                match (vma, size) {
                    (Some(vma), Some(size)) => Ok(Section {
                        name: text(row, "name"),
                        vma,
                        size,
                        executable: row
                            .get("executable")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false),
                        file_offset: row.get("file_offset").and_then(number),
                        file_size: row.get("file_size").and_then(number),
                    }),
                    _ => Err(format!(
                        "{name}: a section has an address (`vma`) and a `size`"
                    )),
                }
            })
            .collect::<Result<Vec<Section>, String>>()?;
        let named = |key: &str| -> Vec<(u64, String)> {
            rows(key)
                .into_iter()
                .filter_map(|row| Some((row.get("address").and_then(number)?, text(row, "name"))))
                .collect()
        };
        let data = rows("data")
            .into_iter()
            .filter_map(|row| {
                Some((
                    row.get("address").and_then(number)?,
                    text(row, "name"),
                    row.get("size").and_then(number).unwrap_or(0),
                ))
            })
            .collect();
        Ok(LoadedImage {
            language,
            entry: object.get("entry").and_then(number),
            base: object.get("base").and_then(number),
            sections,
            functions: named("functions"),
            data,
            imports: named("imports"),
        })
    }
}

impl Architecture for ExternalArchitecture {
    fn name(&self) -> &str {
        &self.name
    }

    fn lifts(&self, _language: &str) -> bool {
        self.lift.is_some()
    }

    fn blocks(
        &self,
        language: &str,
        disasm: &Disasm,
        entry: u64,
    ) -> Option<Result<Vec<RecoveredBlock>, String>> {
        let command = self.blocks.as_ref()?;
        let request = serde_json::json!({
            "language": language,
            "entry": entry,
            "entry_hex": format!("{entry:#x}"),
            "instructions": instructions_json(disasm),
        });
        Some(self.ask(command, &request).and_then(|answer| {
            let rows = answer
                .get("blocks")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| format!("{}: the answer lists `blocks`", self.name))?;
            rows.iter()
                .map(|row| {
                    let from = row.get("from").and_then(number).ok_or_else(|| {
                        format!("{}: a block names where it is `from`", self.name)
                    })?;
                    let to = row.get("to").and_then(number).ok_or_else(|| {
                        format!("{}: a block names where it runs `to`", self.name)
                    })?;
                    Ok(RecoveredBlock {
                        from,
                        to,
                        successors: numbers(row.get("successors")),
                        calls: numbers(row.get("calls")),
                    })
                })
                .collect()
        }))
    }

    fn lift(&self, function: &FunctionCode) -> Option<Result<LiftedGraph, String>> {
        let command = self.lift.as_ref()?;
        let request = serde_json::json!({
            "language": function.language,
            "function": function.address,
            "function_hex": format!("{:#x}", function.address),
            "name": function.name,
            "base": function.base,
            "base_hex": format!("{:#x}", function.base),
            "bytes": hex_text(function.bytes),
            "instructions": instructions_json(function.disasm),
            "blocks": function.cfg.blocks.iter().map(|block| serde_json::json!({
                "from": block.from,
                "from_hex": format!("{:#x}", block.from),
                "to": block.to,
                "to_hex": format!("{:#x}", block.to),
                "successors": block.successor_addresses,
            })).collect::<Vec<_>>(),
        });
        Some(self.ask(command, &request).and_then(|answer| {
            graph_of(&answer).map_err(|error| format!("{}: {error}", self.name))
        }))
    }

    fn languages(&self) -> Vec<String> {
        self.languages.clone()
    }

    fn bitness(&self, _language: &str) -> Bitness {
        self.bitness
    }

    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let request = serde_json::json!({
            "language": language,
            "base": base,
            "bytes": hex,
        });
        let answer = answer_json(&self.command, request.to_string().as_bytes(), self.timeout)?;
        let rows = answer
            .get("instructions")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("{}: the answer lists `instructions`", self.name))?;
        let end = base.saturating_add(bytes.len() as u64);
        let mut decoded = DecodedSection::default();
        let mut dropped = 0usize;
        for row in rows {
            let row = row
                .as_object()
                .ok_or_else(|| format!("{}: an instruction is a JSON object", self.name))?;
            let address = row
                .get("address")
                .and_then(number)
                .ok_or_else(|| format!("{}: an instruction has an address", self.name))?;
            let length = row
                .get("length")
                .and_then(number)
                .filter(|length| *length >= 1)
                .ok_or_else(|| format!("{}: an instruction has a length from 1", self.name))?;
            // An instruction outside the section, or running past its end,
            // is no instruction of it.
            if address < base || address >= end || length > end - address {
                dropped += 1;
                continue;
            }
            let target = row.get("target").and_then(number);
            let flow = match row
                .get("flow")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("next")
            {
                "next" => Flow::Next,
                "jump" => target.map_or(Flow::IndirectBranch, Flow::UnconditionalBranch),
                "branch" => target.map_or(Flow::IndirectBranch, Flow::ConditionalBranch),
                "call" => target.map_or(Flow::IndirectCall, Flow::Call),
                "indirect-jump" => Flow::IndirectBranch,
                "indirect-call" => Flow::IndirectCall,
                "return" => Flow::Return,
                "halt" => Flow::Halt,
                "trap" => Flow::Trap,
                "interrupt" => Flow::Interrupt,
                "syscall" => Flow::Syscall,
                "invalid" => Flow::Invalid,
                other => {
                    return Err(format!(
                        "{}: the flow {other:?} is not one the engine knows",
                        self.name
                    ))
                }
            };
            if decoded.text.contains_key(&address) {
                // The first word on an address is the one kept.
                dropped += 1;
                continue;
            }
            decoded.disasm.instructions.push(DecodedInsn {
                address,
                length: length as usize,
                mnemonic: 0,
                flow,
                operands: Vec::new(),
                register_uses: Vec::new(),
                rip_relative_address: None,
                absolute_address: row.get("memory").and_then(number),
                switch_indices: false,
                opcode: 0,
                flags_read: 0,
                flags_written: 0,
            });
            decoded.text.insert(
                address,
                (
                    row.get("mnemonic")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("?")
                        .to_string(),
                    row.get("operands")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    strings(row.get("registers")),
                ),
            );
        }
        if dropped > 0 {
            eprintln!(
                "warning: {} gave {dropped} instruction(s) outside the section at {base:#x}, or on an address twice; they were left out",
                self.name
            );
        }
        decoded
            .disasm
            .instructions
            .sort_by_key(|instruction| instruction.address);
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory in the temporary directory, removed when the test ends.
    struct Dir(PathBuf);

    impl Dir {
        fn new(stem: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "ag-engine-plugins-{stem}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A toy format: `TOY!`, then a byte of code length, then the code.
    struct ToyLoader;

    impl Loader for ToyLoader {
        fn name(&self) -> &str {
            "toy"
        }
        fn recognizes(&self, bytes: &[u8]) -> bool {
            bytes.starts_with(b"TOY!")
        }
        fn load(&self, _name: &str, bytes: &[u8]) -> Result<LoadedImage, String> {
            let length = *bytes.get(4).ok_or("short")? as u64;
            Ok(LoadedImage {
                language: "TOY:LE:8:default".to_string(),
                entry: Some(0x100),
                base: Some(0x100),
                sections: vec![Section {
                    name: "code".to_string(),
                    vma: 0x100,
                    size: length,
                    executable: true,
                    file_offset: Some(5),
                    file_size: Some(length),
                }],
                functions: vec![(0x100, "start".to_string())],
                data: Vec::new(),
                imports: Vec::new(),
            })
        }
    }

    /// A loader that recognizes an ELF and fails: the engine reads the
    /// file after all.
    struct Failing;

    impl Loader for Failing {
        fn name(&self) -> &str {
            "failing"
        }
        fn recognizes(&self, bytes: &[u8]) -> bool {
            bytes.starts_with(b"FAIL")
        }
        fn load(&self, _name: &str, _bytes: &[u8]) -> Result<LoadedImage, String> {
            Err("not today".to_string())
        }
    }

    #[test]
    fn a_registered_loader_reads_its_format_and_the_image_reports_it() {
        register_loader(Arc::new(ToyLoader));
        let image = crate::image::Image::from_bytes("a.toy", b"TOY!\x03\x01\x02\x00".to_vec())
            .expect("the toy loader reads it");
        assert_eq!(image.language(), "TOY:LE:8:default");
        assert_eq!(image.entry(), Some(0x100));
        assert_eq!(image.load_base(), Some(0x100));
        let sections = image.sections();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].vma, 0x100);
        assert!(sections[0].executable);
        assert_eq!(image.bytes_from(0x100), Some(&[1u8, 2, 0][..]));
        assert_eq!(image.function_symbols(), vec![(0x100, "start".to_string())]);
        assert_eq!(image.function_name(0x100).as_deref(), Some("start"));
        assert!(image.raw().is_none());
        assert!(image.plugin_loaded().is_some());
        // A file the toy loader does not recognize goes to the engine's own
        // loaders, which refuse what is not a container.
        assert!(crate::image::Image::from_bytes("b", b"nothing here".to_vec()).is_err());
        // A loader that fails hands the file on: the engine's loaders have
        // their say, and refuse this one too, in their own words.
        register_loader(Arc::new(Failing));
        let error = crate::image::Image::from_bytes("c", b"FAIL and then some".to_vec())
            .unwrap_err()
            .to_string();
        assert!(error.contains("loading c"), "{error}");
        assert!(!error.contains("not today"), "{error}");
    }

    fn two_blocks() -> Rewrite {
        let statement = |text: &str| Rewrite::statement(AstNode::var(text), vec![0x10]);
        Rewrite::new(
            0x1000,
            "f",
            0,
            vec![
                Node {
                    address: 0x1000,
                    statements: vec![statement("a"), statement("b")],
                    terminator: Terminator::Branch {
                        cond: AstNode::var("c"),
                        taken: 1,
                        next: 0,
                        addresses: vec![0x1004],
                    },
                },
                Node {
                    address: 0x1010,
                    statements: vec![statement("d")],
                    terminator: Terminator::Return,
                },
            ],
        )
    }

    #[test]
    fn a_rewrite_moves_statements_adds_blocks_and_points_the_ways_out() {
        let mut rewrite = two_blocks();
        assert!(!rewrite.changed());
        let copied = rewrite.copy_statement(0, 1).unwrap();
        assert!(!rewrite.changed());
        rewrite.insert_statement(1, 0, copied).unwrap();
        assert_eq!(rewrite.nodes[1].statements.len(), 2);
        rewrite.remove_statement(0, 0).unwrap();
        assert_eq!(rewrite.nodes[0].statements.len(), 1);
        assert!(rewrite.remove_statement(0, 5).is_err());
        assert!(rewrite.remove_statement(9, 0).is_err());
        // A new block with a copy, entered by the loop's back edge.
        let fresh = rewrite.fresh_address();
        assert_eq!(fresh, 0x1011);
        let copied = rewrite.copy_statement(1, 1).unwrap();
        let added = rewrite
            .add_block(
                fresh,
                vec![copied.clone()],
                Terminator::Goto {
                    target: 1,
                    addresses: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(added, 2);
        // An address in use labels a block already; a way out past the end
        // is refused too.
        assert!(rewrite
            .add_block(0x1000, Vec::new(), Terminator::Return)
            .unwrap_err()
            .contains("block 0 has the address 0x1000 already"));
        assert!(rewrite
            .add_block(
                0x2000,
                vec![copied],
                Terminator::Goto {
                    target: 9,
                    addresses: Vec::new()
                }
            )
            .is_err());
        rewrite.redirect(0, 0, added).unwrap();
        assert_eq!(rewrite.nodes[0].terminator.successors(), vec![1, 2]);
        assert!(rewrite.redirect(1, 0, 1).is_err(), "a return leads nowhere");
        assert!(rewrite.redirect(0, 1, 7).is_err(), "no block 7");
        rewrite.set_goto(0, 1).unwrap();
        assert!(matches!(
            rewrite.nodes[0].terminator,
            Terminator::Goto { target: 1, ref addresses } if addresses == &[0x1004]
        ));
        rewrite.set_branch(2, AstNode::var("c"), 0, 1).unwrap();
        assert!(rewrite.set_branch(2, AstNode::var("c"), 0, 9).is_err());
        rewrite.set_return(2).unwrap();
        rewrite.validate().unwrap();
        assert!(rewrite.changed());
        // Block 2 is cut off: pruning drops it and renumbers nothing else.
        assert_eq!(rewrite.prune_unreachable(), 1);
        assert_eq!(rewrite.nodes.len(), 2);
        assert_eq!(rewrite.prune_unreachable(), 0);
        // Pruning renumbers the blocks after the ones dropped.
        let mut rewrite = two_blocks();
        let third = rewrite
            .add_block(0x1020, Vec::new(), Terminator::Return)
            .unwrap();
        rewrite.set_goto(0, third).unwrap();
        assert_eq!(rewrite.prune_unreachable(), 1);
        assert_eq!(rewrite.nodes.len(), 2);
        assert!(matches!(
            rewrite.nodes[0].terminator,
            Terminator::Goto { target: 1, .. }
        ));
        assert_eq!(rewrite.nodes[1].address, 0x1020);
        rewrite.validate().unwrap();
        // A switch's cases are renumbered with the rest.
        let mut rewrite = two_blocks();
        let third = rewrite
            .add_block(0x1020, Vec::new(), Terminator::Return)
            .unwrap();
        rewrite
            .set_terminator(
                0,
                Terminator::Switch {
                    index: AstNode::var("i"),
                    cases: vec![(vec![0], third), (vec![1], 0)],
                    addresses: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(rewrite.prune_unreachable(), 1);
        assert!(matches!(
            &rewrite.nodes[0].terminator,
            Terminator::Switch { cases, .. } if cases == &vec![(vec![0], 1), (vec![1], 0)]
        ));
        // Two blocks at one address do not validate.
        let mut rewrite = two_blocks();
        rewrite.nodes[1].address = 0x1000;
        assert!(rewrite.validate().unwrap_err().contains("both at 0x1000"));
        // Redirecting a way to where it already leads changes nothing.
        let mut rewrite = two_blocks();
        rewrite.redirect(0, 1, 1).unwrap();
        assert!(!rewrite.changed());
        // A command's filter.
        let external = ExternalRewriter {
            name: "x".to_string(),
            command: vec!["true".to_string()],
            timeout: Duration::from_secs(1),
            functions: vec!["main".to_string(), "0x1161".to_string()],
        };
        assert!(external.wants(0x1198, "main"));
        assert!(external.wants(0x1161, "sum_to"));
        assert!(!external.wants(0x1149, "add"));
        rewrite.nodes[0].terminator = Terminator::Goto {
            target: 5,
            addresses: Vec::new(),
        };
        assert!(rewrite
            .validate()
            .unwrap_err()
            .contains("block 0 leading to block 5"));
    }

    #[test]
    fn a_commands_edits_are_applied_in_order_and_a_bad_one_is_named() {
        let mut rewrite = two_blocks();
        let json = rewrite.to_json();
        assert_eq!(json["blocks"][0]["statements"][1]["text"], "b");
        assert_eq!(json["blocks"][0]["terminator"]["kind"], "branch");
        assert_eq!(json["blocks"][0]["terminator"]["cond"], "c");
        assert_eq!(json["blocks"][1]["terminator"]["kind"], "return");
        rewrite
            .apply_edits(&serde_json::json!({ "edits": [
                { "op": "move", "from": 0, "statement": 0, "to": 1, "at": 0 },
                { "op": "add_block", "statements": [{ "from": 1, "statement": 1 }],
                  "terminator": { "kind": "branch", "cond_of": 0, "taken": 1, "next": 0 } },
                { "op": "redirect", "block": 0, "from": 0, "to": 2 },
                { "op": "copy", "from": 1, "statement": 0, "to": 2 },
                { "op": "goto", "block": 2, "target": 1 },
            ] }))
            .unwrap();
        assert_eq!(rewrite.nodes.len(), 3);
        assert_eq!(rewrite.nodes[0].statements.len(), 1);
        assert_eq!(rewrite.nodes[1].statements.len(), 2);
        assert_eq!(rewrite.nodes[2].statements.len(), 2);
        assert_eq!(rewrite.nodes[2].address, 0x1011);
        assert_eq!(rewrite.nodes[0].terminator.successors(), vec![1, 2]);
        assert!(matches!(
            rewrite.nodes[2].terminator,
            Terminator::Goto { target: 1, .. }
        ));
        rewrite.validate().unwrap();
        // Nothing to do is fine; a bad edit says which.
        rewrite.apply_edits(&serde_json::json!({})).unwrap();
        rewrite.apply_edits(&serde_json::Value::Null).unwrap();
        let error = rewrite
            .apply_edits(&serde_json::json!([{ "op": "remove", "block": 0, "statement": 4 }]))
            .unwrap_err();
        assert!(
            error.starts_with("edit 0 (remove): block 0 has no statement 4"),
            "{error}"
        );
        let error = rewrite
            .apply_edits(&serde_json::json!([{ "op": "add_block", "statements": [] }]))
            .unwrap_err();
        assert!(error.contains("names its terminator"), "{error}");
        let error = rewrite
            .apply_edits(&serde_json::json!([{ "op": "fold" }]))
            .unwrap_err();
        assert!(error.contains("no such op"), "{error}");
        let error = rewrite
            .apply_edits(&serde_json::json!([{ "op": "branch", "block": 0, "cond_of": 1, "taken": 0, "next": 1 }]))
            .unwrap_err();
        assert!(error.contains("does not branch"), "{error}");
        assert!(rewrite.apply_edits(&serde_json::json!("edits")).is_err());
    }

    #[test]
    fn a_commands_expression_trees_and_lifted_function_read_back() {
        let tree = serde_json::json!({
            "assign": "x",
            "rhs": { "binary": "+", "lhs": { "deref": { "var": "p" } }, "rhs": { "const": 1, "width": 4 } }
        });
        let node = expression(&tree).unwrap();
        assert_eq!(
            crate::emit::emit_node(&node)
                .trim_end()
                .trim_end_matches(';'),
            "x = *p + 1"
        );
        let call = expression(&serde_json::json!({
            "call": "puts", "address": "0x300", "args": [{ "string": "hi" }, 7, true]
        }))
        .unwrap();
        assert!(
            matches!(&call, AstNode::Call { callee, args } if matches!(**callee, AstNode::FunctionName { ref name, address: 0x300 } if name == "puts") && args.len() == 3)
        );
        assert!(matches!(
            expression(&serde_json::json!({ "return": { "cast": "long", "target": "x" } }))
                .unwrap(),
            AstNode::Return { value: Some(_) }
        ));
        assert!(
            expression(&serde_json::json!({ "binary": "<>", "lhs": 1, "rhs": 2 }))
                .unwrap_err()
                .contains("no such operator")
        );
        assert!(expression(&serde_json::json!({ "fold": 1 })).is_err());
        assert!(expression(&serde_json::json!([1])).is_err());

        let graph = graph_of(&serde_json::json!({
            "return_type": "int",
            "params": [{ "name": "n", "type": "int" }],
            "locals": [{ "name": "flag" }],
            "entry": 0,
            "frame": ["0x100"],
            "blocks": [
                { "address": "0x100", "statements": [{ "addresses": ["0x102"], "expr": { "call": "sub_10a", "args": [] } }],
                  "terminator": { "kind": "branch", "cond": "flag", "taken": 1, "next": 2, "addresses": ["0x104"] } },
                { "address": "0x106", "statements": [], "terminator": { "kind": "goto", "target": 2 } },
                { "address": "0x108", "statements": [{ "addresses": ["0x108"], "expr": { "return": "n" } }],
                  "terminator": { "kind": "return" } }
            ]
        }))
        .unwrap();
        assert_eq!(graph.return_type, "int");
        assert_eq!(graph.params[0].name, "n");
        assert_eq!(graph.locals[0].ty, "long", "a type unsaid is long");
        assert_eq!(graph.nodes.len(), 3);
        assert_eq!(graph.frame, vec![0x100]);
        assert!(matches!(
            graph.nodes[0].terminator,
            Terminator::Branch {
                taken: 1,
                next: 2,
                ..
            }
        ));
        // A block pointing outside the function is refused.
        let error = graph_of(&serde_json::json!({
            "blocks": [{ "address": 1, "terminator": { "kind": "goto", "target": 4 } }]
        }))
        .unwrap_err();
        assert!(error.contains("block 0 leading to block 4"), "{error}");
        assert!(graph_of(
            &serde_json::json!({ "blocks": [{ "address": 1, "terminator": { "kind": "fly" } }] })
        )
        .is_err());
        assert_eq!(hex_text(&[0x54, 0x4f, 0x01]), "544f01");
        assert_eq!(
            flow_name(&Flow::ConditionalBranch(0x104)),
            ("branch", Some(0x104))
        );
    }

    #[test]
    fn numbers_read_as_json_numbers_or_hex_text() {
        assert_eq!(number(&serde_json::json!(16)), Some(16));
        assert_eq!(number(&serde_json::json!("0x10")), Some(16));
        assert_eq!(number(&serde_json::json!("16")), Some(16));
        assert_eq!(number(&serde_json::json!("sixteen")), None);
        assert_eq!(number(&serde_json::json!("+16")), None);
        assert_eq!(hex_bytes("54 4f 59 21"), Some(b"TOY!".to_vec()));
        assert_eq!(hex_bytes("544"), None);
        assert_eq!(hex_bytes(""), None);
        // Not ASCII: refused, not a panic on a split character.
        assert_eq!(hex_bytes("aé1"), None);
        assert_eq!(hex_bytes("zz"), None);
    }

    #[test]
    fn a_manifest_declares_its_three_kinds_and_a_bad_one_says_what_is_wrong() {
        let dir = Dir::new("manifest");
        let path = dir.0.join("demo.json");
        std::fs::write(
            &path,
            r#"{
                "name": "demo",
                "loaders": [{ "name": "manifile", "magic": "4d414e49", "command": ["sh", "-c", "cat"], "timeout": 5 }],
                "architectures": [{ "languages": ["MANI:LE:8:default"], "bitness": "32", "command": ["python3", "decode.py"] }, { "languages": ["MANI:LE:16:default"], "bitness": 16, "command": ["${dir}/sub/decode"] }],
                "tools": [{ "name": "count-strings", "description": "Counts.", "command": ["sh", "-c", "cat"], "inputSchema": { "type": "object" } }]
            }"#,
        )
        .unwrap();
        let manifest = read_manifest(&path).expect("reads");
        assert_eq!(manifest.name, "demo");
        assert_eq!(manifest.loaders[0].name, "manifile");
        assert_eq!(manifest.loaders[0].magic, b"MANI");
        assert_eq!(manifest.loaders[0].timeout, Duration::from_secs(5));
        // Unnamed entries are named for the manifest, the second with its
        // place; a relative path is the manifest directory's, a bare
        // program name is left for PATH, and `${dir}` is the directory.
        assert_eq!(manifest.architectures[0].name, "demo");
        assert_eq!(manifest.architectures[1].name, "demo-1");
        assert_eq!(manifest.architectures[0].bitness, Bitness::Bits32);
        assert_eq!(manifest.architectures[1].bitness, Bitness::Bits16);
        assert_eq!(manifest.architectures[0].command[0], "python3");
        assert_eq!(manifest.architectures[0].command[1], "decode.py");
        assert_eq!(
            manifest.architectures[1].command[0],
            dir.0.join("sub/decode").display().to_string()
        );
        assert_eq!(manifest.tools[0].name, "count-strings");
        assert_eq!(manifest.tools[0].timeout, DEFAULT_TIMEOUT);
        assert!(manifest.tools[0].input_schema.is_some());
        std::fs::write(
            dir.0.join("bad.json"),
            r#"{ "loaders": [{ "name": "x", "command": ["cat"] }] }"#,
        )
        .unwrap();
        let error = read_manifest(&dir.0.join("bad.json")).unwrap_err();
        assert!(error.contains("magic"), "{error}");
        std::fs::write(
            dir.0.join("tool.json"),
            r#"{ "tools": [{ "name": "no spaces here", "command": ["cat"] }] }"#,
        )
        .unwrap();
        let error = read_manifest(&dir.0.join("tool.json")).unwrap_err();
        assert!(error.contains("letters, digits"), "{error}");
        std::fs::write(
            dir.0.join("schema.json"),
            r#"{ "tools": [{ "name": "t", "command": ["cat"], "inputSchema": 5 }] }"#,
        )
        .unwrap();
        assert!(read_manifest(&dir.0.join("schema.json"))
            .unwrap_err()
            .contains("inputSchema"));
        std::fs::write(
            dir.0.join("width.json"),
            r#"{ "architectures": [{ "languages": ["X"], "bitness": 24, "command": ["cat"] }] }"#,
        )
        .unwrap();
        assert!(read_manifest(&dir.0.join("width.json"))
            .unwrap_err()
            .contains("16, 32 or 64"));
        std::fs::write(
            dir.0.join("twice.json"),
            r#"{ "name": "twice", "tools": [{ "name": "count-strings", "command": ["cat"] }] }"#,
        )
        .unwrap();
        let (manifests, problems) = load_manifests(std::slice::from_ref(&dir.0));
        assert_eq!(manifests.len(), 2, "{problems:?}");
        assert_eq!(problems.len(), 5, "{problems:?}");
        assert!(
            problems.iter().any(|p| p.contains("declared again")),
            "{problems:?}"
        );
        assert!(loaders().iter().any(|loader| loader.name() == "manifile"));
        assert!(architecture_for("MANI:LE:8:default").is_some());
    }

    #[test]
    fn an_external_architecture_turns_the_answer_into_instructions_with_flow() {
        // `sh -c` answers with fixed JSON whatever it is asked: three good
        // instructions, one outside the section and one on an address
        // already taken, which are left out.
        let architecture = ExternalArchitecture {
            name: "fixed".to_string(),
            languages: vec!["FIXED:LE:32:default".to_string()],
            bitness: Bitness::Bits32,
            timeout: DEFAULT_TIMEOUT,
            blocks: None,
            lift: None,
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                concat!(
                    "cat >/dev/null; printf '%s' '{\"instructions\":[",
                    "{\"address\":\"0x100\",\"length\":2,\"mnemonic\":\"mov\",\"operands\":\"r0, 1\",\"registers\":[\"r0\"],\"memory\":\"0x2000\"},",
                    "{\"address\":258,\"length\":2,\"mnemonic\":\"beq\",\"operands\":\"0x104\",\"flow\":\"branch\",\"target\":260},",
                    "{\"address\":260,\"length\":2,\"mnemonic\":\"ret\",\"flow\":\"return\"},",
                    "{\"address\":\"0xffffffffffffffff\",\"length\":2,\"mnemonic\":\"far\"},",
                    "{\"address\":262,\"length\":9,\"mnemonic\":\"long\"},",
                    "{\"address\":258,\"length\":2,\"mnemonic\":\"again\"}]}'"
                )
                .to_string(),
            ],
        };
        let decoded = architecture
            .decode_section("FIXED:LE:32:default", &[0; 6], 0x100)
            .expect("decodes");
        assert_eq!(decoded.disasm.instructions.len(), 3);
        assert_eq!(decoded.disasm.instructions[0].flow, Flow::Next);
        assert_eq!(
            decoded.disasm.instructions[0].absolute_address,
            Some(0x2000)
        );
        assert_eq!(
            decoded.disasm.instructions[1].flow,
            Flow::ConditionalBranch(260)
        );
        assert_eq!(decoded.disasm.instructions[2].flow, Flow::Return);
        assert_eq!(
            decoded.text.get(&0x100),
            Some(&(
                "mov".to_string(),
                "r0, 1".to_string(),
                vec!["r0".to_string()]
            ))
        );
        assert_eq!(decoded.text.get(&258).map(|t| t.0.as_str()), Some("beq"));
        let failing = ExternalArchitecture {
            command: vec!["sh".to_string(), "-c".to_string(), "exit 2".to_string()],
            ..architecture.clone()
        };
        let error = failing
            .decode_section("FIXED:LE:32:default", &[0; 2], 0x100)
            .unwrap_err();
        assert!(error.contains("ended with"), "{error}");
        // A command past its time is ended.
        let slow = ExternalArchitecture {
            command: vec!["sh".to_string(), "-c".to_string(), "sleep 5".to_string()],
            timeout: Duration::from_secs(1),
            ..architecture
        };
        let started = Instant::now();
        let error = slow
            .decode_section("FIXED:LE:32:default", &[0; 2], 0x100)
            .unwrap_err();
        assert!(error.contains("within 1 seconds"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(4));
    }
}
