//! The intermediate languages: the lift at every level it passes through,
//! each a sequence of items with the addresses they came from, and each
//! with a static single assignment form.
//!
//! The lifter goes from the machine's instructions to a C-like tree in
//! stages, and each stage is a language of its own:
//!
//! - the **lifted** level is the machine's instructions, one item each,
//!   with the registers each reads and writes and where its flow goes;
//! - the **low** level is the lifter's statements over temporaries, stack
//!   slots and registers, before the temporaries are resolved — one or
//!   more per instruction, a `branch if` or `switch on` at a chain's end;
//! - the **medium** level is the statements over variables and
//!   parameters, calls resolved with their arguments, laid on the chain
//!   graph with a `goto`, `branch` or `switch` at each chain's end;
//! - the **high** level is the structured body: `if`, `while`, `for`,
//!   `switch` and `return`, as the pseudocode prints them, each item at
//!   its depth in the tree.
//!
//! The lifted, low and medium levels lie on the same graph of chains, so
//! an item of one maps onto the items of another through the addresses
//! they share ([`correspondence`]); the high level's items carry the same
//! addresses. The SSA form ([`to_ssa`]) gives every definition of a name a
//! version — `x#1`, `x#2` — and puts a φ item where paths with different
//! versions meet, by the dominance frontiers of the chain graph; the high
//! level takes its versions from the medium level's statements, which it
//! is a rearrangement of.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::ast::AstNode;
use crate::cpu_context::{Access, DecodedInsn, Flow};
use crate::lift::{Stages, Statement, StatementKind};
use crate::pipeline::Disasm;
use crate::structure::{Analysis, Terminator};

/// A level of the lift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    /// The machine's instructions, one item each.
    Lifted,
    /// The lifter's statements over temporaries and slots.
    Low,
    /// Statements over variables, on the chain graph.
    Medium,
    /// The structured body.
    High,
}

impl Level {
    /// The level's name, as the command line spells it.
    pub fn name(self) -> &'static str {
        match self {
            Level::Lifted => "lifted",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
        }
    }

    /// The level a name spells.
    pub fn parse(text: &str) -> Option<Level> {
        match text.trim().to_ascii_lowercase().as_str() {
            "lifted" => Some(Level::Lifted),
            "low" => Some(Level::Low),
            "medium" => Some(Level::Medium),
            "high" => Some(Level::High),
            _ => None,
        }
    }

    /// Every level, lowest first.
    pub const ALL: [Level; 4] = [Level::Lifted, Level::Low, Level::Medium, Level::High];
}

/// One item of a level: an instruction, a statement, a φ.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IlItem {
    /// The item's number in the function, from 0.
    pub id: usize,
    /// The block the item is in.
    pub block: usize,
    /// How deep the item sits in the tree, at the high level; 0 elsewhere.
    pub depth: usize,
    /// The machine addresses the item came from.
    pub addresses: Vec<u64>,
    /// The item, as text.
    pub text: String,
    /// The names the item writes: registers, temporaries, slots, variables
    /// — with their versions in SSA form.
    pub defines: Vec<String>,
    /// The names the item reads.
    pub uses: Vec<String>,
    /// Whether the item is a φ of SSA form.
    pub phi: bool,
    /// What the item is: at the lifted level the instruction's form as the
    /// decoder numbers it (`Mov_r32_rm32`), at the others the statement's
    /// kind — `assign`, `store`, `call`, `intrinsic`, `return`, `compare`,
    /// `branch`, `switch`, `goto`, `label`, `break`, `continue`,
    /// `expression`, `if`, `else`, `while`, `do`, `for`, `case`, `phi`.
    /// None for an instruction the decoder has no form for.
    pub opcode: Option<String>,
    /// The flags the instruction reads, at the lifted level: `CF`, `ZF`, …
    pub flags_read: Vec<String>,
    /// The flags the instruction writes, at the lifted level.
    pub flags_written: Vec<String>,
    /// The stack pointer's offset from the entry's before the item's first
    /// instruction, where the lifter knew it.
    pub stack_pointer: Option<i64>,
    /// The C type of each name the item reads or writes, by its plain
    /// name: `local_14: int`; at the lifted level the registers as the
    /// text spells them, typed by their width: `eax: int`. A temporary
    /// whose width was never read is `long`; a slot stored at two widths
    /// has the first; the flags are `flags`.
    pub types: Vec<(String, String)>,
}

/// What a level's text shows beside each item, over the item itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Render {
    /// The item's opcode before it, in brackets.
    pub opcodes: bool,
    /// The flags an instruction reads and writes.
    pub flags: bool,
    /// The stack pointer's offset from the entry's.
    pub stack_pointer: bool,
    /// The type of every name the item uses.
    pub types: bool,
}

impl Render {
    /// Everything shown.
    pub const ALL: Render = Render {
        opcodes: true,
        flags: true,
        stack_pointer: true,
        types: true,
    };

    /// Whether anything is shown beside the items.
    pub fn any(self) -> bool {
        self.opcodes || self.flags || self.stack_pointer || self.types
    }
}

/// One block of a level: a chain of the lift at the lifted, low and
/// medium levels; the one block of the whole body at the high level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IlBlock {
    pub id: usize,
    /// The address of the first instruction.
    pub address: u64,
    /// The blocks this one goes on to.
    pub successors: Vec<usize>,
    /// The items, by id, in order.
    pub items: Vec<usize>,
}

/// A function at one level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IlFunction {
    pub name: String,
    pub address: u64,
    pub level: Level,
    /// Whether the names carry versions and the blocks their φs.
    pub ssa: bool,
    pub blocks: Vec<IlBlock>,
    pub items: Vec<IlItem>,
}

impl IlFunction {
    /// The function as text: a header, then each block's label and its
    /// items, indented by depth.
    pub fn text(&self) -> String {
        self.render(&Render::default())
    }

    /// One item as text, with what `render` asks for beside it: its opcode
    /// in brackets before it, then notes — the stack pointer, the flags,
    /// the types — each after `  ; `.
    pub fn item_text(&self, item: &IlItem, render: &Render) -> String {
        let mut text = String::new();
        if render.opcodes {
            if let Some(opcode) = &item.opcode {
                text.push_str(&format!("[{opcode}] "));
            }
        }
        text.push_str(&item.text);
        if render.stack_pointer {
            if let Some(offset) = item.stack_pointer {
                text.push_str(&format!("  ; sp = entry{}", offset_text(offset)));
            }
        }
        if render.flags && !(item.flags_read.is_empty() && item.flags_written.is_empty()) {
            let list = |flags: &[String]| {
                if flags.is_empty() {
                    "none".to_string()
                } else {
                    flags.join(" ")
                }
            };
            text.push_str(&format!(
                "  ; flags: reads {}, writes {}",
                list(&item.flags_read),
                list(&item.flags_written)
            ));
        }
        if render.types && !item.types.is_empty() {
            text.push_str(&format!(
                "  ; types: {}",
                item.types
                    .iter()
                    .map(|(name, ty)| format!("{name}: {ty}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        text
    }

    /// The function as text with what `render` asks for beside each item.
    pub fn render(&self, render: &Render) -> String {
        let mut out = format!(
            "; {} at {:#x}: {} level{}\n",
            self.name,
            self.address,
            self.level.name(),
            if self.ssa { ", SSA form" } else { "" }
        );
        if self.blocks.is_empty() {
            out.push_str("; no blocks at this level\n");
        }
        for block in &self.blocks {
            if self.level != Level::High {
                let successors: Vec<String> = block
                    .successors
                    .iter()
                    .filter_map(|id| self.blocks.get(*id))
                    .map(|block| format!("{:#x}", block.address))
                    .collect();
                out.push_str(&format!(
                    "block_{:x}:{}\n",
                    block.address,
                    if successors.is_empty() {
                        String::new()
                    } else {
                        format!("  ; -> {}", successors.join(", "))
                    }
                ));
            }
            for id in &block.items {
                let item = &self.items[*id];
                let at = match item.addresses.first() {
                    Some(address) if item.addresses.len() == 1 => format!("{address:08x}"),
                    Some(address) => format!("{address:08x}+"),
                    None => "        ".to_string(),
                };
                out.push_str(&format!(
                    "  {at}  {}{}\n",
                    "    ".repeat(item.depth),
                    self.item_text(item, render)
                ));
            }
        }
        out
    }

    /// The items whose addresses include `address`.
    pub fn items_at(&self, address: u64) -> Vec<&IlItem> {
        self.items
            .iter()
            .filter(|item| item.addresses.contains(&address))
            .collect()
    }
}

/// A stack offset as text after `entry`: nothing, `-0x14`, `+0x8`.
fn offset_text(offset: i64) -> String {
    match offset {
        0 => String::new(),
        negative if negative < 0 => format!("-{:#x}", -negative),
        positive => format!("+{positive:#x}"),
    }
}

/// The width a general register's spelling names, in bits: `rax` 64,
/// `eax` 32, `ax` 16, `al` 8, `r8d` 32; none for another register.
pub fn register_width(name: &str) -> Option<u32> {
    let name = name.to_ascii_lowercase();
    const WIDE: [&str; 9] = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    ];
    const WORD: [&str; 8] = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"];
    const BYTE: [&str; 12] = [
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl",
    ];
    if WIDE.contains(&name.as_str()) {
        return Some(64);
    }
    if let Some(rest) = name.strip_prefix('e') {
        if WORD.contains(&rest) || rest == "ip" {
            return Some(32);
        }
    }
    if WORD.contains(&name.as_str()) {
        return Some(16);
    }
    if BYTE.contains(&name.as_str()) {
        return Some(8);
    }
    // r8 to r15, and their d, w and b (or l) parts.
    let numbered = name.strip_prefix('r')?;
    let (digits, suffix) = numbered.split_at(numbered.trim_end_matches(['d', 'w', 'b', 'l']).len());
    let number: u32 = digits.parse().ok()?;
    if !(8..=15).contains(&number) {
        return None;
    }
    match suffix {
        "" => Some(64),
        "d" => Some(32),
        "w" => Some(16),
        "b" | "l" => Some(8),
        _ => None,
    }
}

/// `node` cast to `ty`: a constant cast once, to that type; anything else
/// wrapped whole, its own constants spelled with their widths.
pub fn cast_to(ty: &str, node: &AstNode) -> AstNode {
    match node {
        AstNode::Constant { .. } => AstNode::Cast {
            ty: ty.to_string(),
            target: Box::new(node.clone()),
        },
        AstNode::Cast { ty: own, .. } if own == ty => node.clone(),
        other => AstNode::Cast {
            ty: ty.to_string(),
            target: Box::new(with_casts(other)),
        },
    }
}

/// The expression with its casts explicit: every constant spelled with the
/// type of its width — `(int)1`, `(long)0` — except under a cast already,
/// or where it is the constant directly dereferenced or taken the address
/// of. The right side of an assignment, both sides of an operator, a call's
/// arguments and a return's value are walked; a condition or a loop's
/// header is not.
pub fn with_casts(node: &AstNode) -> AstNode {
    fn walk(node: &AstNode, under: bool) -> AstNode {
        match node {
            AstNode::Constant { width_bytes, .. } if !under => AstNode::Cast {
                ty: crate::lift::type_name(width_bytes * 8).to_string(),
                target: Box::new(node.clone()),
            },
            AstNode::Cast { ty, target } => AstNode::Cast {
                ty: ty.clone(),
                target: Box::new(walk(target, true)),
            },
            AstNode::Binary { lhs, op, rhs } => AstNode::Binary {
                lhs: Box::new(walk(lhs, false)),
                op: *op,
                rhs: Box::new(walk(rhs, false)),
            },
            AstNode::Assign { lhs, rhs } => AstNode::Assign {
                lhs: lhs.clone(),
                rhs: Box::new(walk(rhs, false)),
            },
            AstNode::Deref { target } => AstNode::Deref {
                target: Box::new(walk(target, true)),
            },
            AstNode::AddressOf { target } => AstNode::AddressOf {
                target: Box::new(walk(target, true)),
            },
            AstNode::Call { callee, args } => AstNode::Call {
                callee: callee.clone(),
                args: args.iter().map(|arg| walk(arg, false)).collect(),
            },
            AstNode::Intrinsic { name, args } => AstNode::Intrinsic {
                name: name.clone(),
                args: args.iter().map(|arg| walk(arg, false)).collect(),
            },
            AstNode::Return { value } => AstNode::Return {
                value: value.as_ref().map(|value| Box::new(walk(value, false))),
            },
            AstNode::Ternary {
                cond,
                then,
                otherwise,
            } => AstNode::Ternary {
                cond: cond.clone(),
                then: Box::new(walk(then, false)),
                otherwise: Box::new(walk(otherwise, false)),
            },
            other => other.clone(),
        }
    }
    walk(node, false)
}

/// The expression as it is, or with its casts explicit.
fn maybe_casts(node: &AstNode, casts: bool) -> std::borrow::Cow<'_, AstNode> {
    if casts {
        std::borrow::Cow::Owned(with_casts(node))
    } else {
        std::borrow::Cow::Borrowed(node)
    }
}

/// What kind of statement an expression is, for the item's opcode.
fn node_kind(node: &AstNode) -> &'static str {
    match node {
        AstNode::Assign { .. } => "assign",
        AstNode::Call { .. } => "call",
        AstNode::Intrinsic { .. } => "intrinsic",
        AstNode::Return { .. } => "return",
        AstNode::Goto { .. } => "goto",
        AstNode::Label { .. } => "label",
        AstNode::IfGoto { .. } => "branch",
        AstNode::Break => "break",
        AstNode::Continue => "continue",
        _ => "expression",
    }
}

/// The C type of a name the levels use, when it is known: from the lift's
/// table, or `long` for a register's value at entry.
fn type_of(name: &str, types: &BTreeMap<String, String>) -> Option<String> {
    let plain = name.rsplit_once('#').map_or(name, |(plain, _)| plain);
    types.get(plain).cloned().or_else(|| {
        plain
            .strip_prefix("entry")
            .filter(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
            .map(|_| "long".to_string())
    })
}

/// Give every item its stack pointer and the types of its names, from the
/// lift's tables; an item that has types already — a lifted-level
/// instruction's registers — keeps them.
fn decorate(function: &mut IlFunction, stages: &Stages) {
    for item in &mut function.items {
        if item.stack_pointer.is_none() {
            item.stack_pointer = item
                .addresses
                .iter()
                .min()
                .and_then(|address| stages.stack_pointer.get(address).copied());
        }
        if item.types.is_empty() {
            for name in item.defines.iter().chain(&item.uses) {
                let plain = name
                    .rsplit_once('#')
                    .map_or(name.as_str(), |(plain, _)| plain);
                if item.types.iter().any(|(known, _)| known == plain) {
                    continue;
                }
                if let Some(ty) = type_of(plain, &stages.types) {
                    item.types.push((plain.to_string(), ty));
                }
            }
        }
    }
}

/// The names an expression reads: its variables and registers, as the
/// emitter spells them, each once in order.
pub fn names_in(node: &AstNode) -> Vec<String> {
    let mut names = Vec::new();
    collect_names(node, &mut names);
    names
}

fn collect_names(node: &AstNode, names: &mut Vec<String>) {
    let mut push = |name: String| {
        if !names.contains(&name) {
            names.push(name);
        }
    };
    match node {
        AstNode::Var { name } => push(name.clone()),
        AstNode::Register { reg } => push(format!("r{}_{}", reg.class, reg.index)),
        AstNode::Assign { lhs, rhs } => {
            collect_names(rhs, names);
            collect_names(lhs, names);
        }
        AstNode::Binary { lhs, rhs, .. } => {
            collect_names(lhs, names);
            collect_names(rhs, names);
        }
        AstNode::Deref { target }
        | AstNode::AddressOf { target }
        | AstNode::Cast { target, .. } => collect_names(target, names),
        AstNode::Call { callee, args } => {
            collect_names(callee, names);
            for arg in args {
                collect_names(arg, names);
            }
        }
        AstNode::Intrinsic { args, .. } => {
            for arg in args {
                collect_names(arg, names);
            }
        }
        AstNode::Return { value } => {
            if let Some(value) = value {
                collect_names(value, names);
            }
        }
        AstNode::If {
            cond,
            then_part,
            else_part,
            ..
        } => {
            collect_names(cond, names);
            collect_names(then_part, names);
            if let Some(else_part) = else_part {
                collect_names(else_part, names);
            }
        }
        AstNode::IfGoto { cond, .. } => collect_names(cond, names),
        AstNode::Loop { cond, body, .. } => {
            if let Some(cond) = cond {
                collect_names(cond, names);
            }
            collect_names(body, names);
        }
        AstNode::ConstantCondition { compared, .. } => collect_names(compared, names),
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => {
            collect_names(cond, names);
            collect_names(then, names);
            collect_names(otherwise, names);
        }
        AstNode::StructInit { fields } => {
            for field in fields {
                collect_names(&field.value, names);
            }
        }
        AstNode::Label { .. }
        | AstNode::Goto { .. }
        | AstNode::Constant { .. }
        | AstNode::FunctionName { .. }
        | AstNode::StringLiteral { .. }
        | AstNode::ConditionTrue
        | AstNode::ConditionFalse
        | AstNode::Break
        | AstNode::Continue => {}
    }
}

/// The name an assignment defines, when its left side is a variable or a
/// register, and the names the statement reads.
fn defines_and_uses(node: &AstNode) -> (Vec<String>, Vec<String>) {
    match node {
        AstNode::Assign { lhs, rhs } => match lhs.as_ref() {
            AstNode::Var { .. } | AstNode::Register { .. } => (names_in(lhs), names_in(rhs)),
            _ => {
                let mut uses = names_in(rhs);
                for name in names_in(lhs) {
                    if !uses.contains(&name) {
                        uses.push(name);
                    }
                }
                (Vec::new(), uses)
            }
        },
        other => (Vec::new(), names_in(other)),
    }
}

/// A line of emitted text, without the newline the emitter ends it with.
fn line(node: &AstNode) -> String {
    crate::emit::emit_node(node)
        .trim_end()
        .trim_end_matches(';')
        .to_string()
}

/// A register as the levels name it.
pub fn register_name(id: crate::register::RegisterId) -> String {
    format!("r{}_{}", id.class, id.index)
}

/// Build the function at `level` from the lift's stages; `text` gives an
/// instruction's mnemonic, operands and named registers for the lifted
/// level, when the caller has them.
pub fn build(
    level: Level,
    stages: &Stages,
    disasm: &Disasm,
    text: &dyn Fn(u64) -> Option<(String, String, Vec<String>)>,
    casts: bool,
) -> IlFunction {
    let mut function = IlFunction {
        name: stages.function.name.clone(),
        address: stages.function.address,
        level,
        ssa: false,
        blocks: Vec::new(),
        items: Vec::new(),
    };
    match level {
        Level::Lifted => {
            for (index, chain) in stages.chains.iter().enumerate() {
                let mut block = IlBlock {
                    id: index,
                    address: chain.address,
                    successors: chain.successors.clone(),
                    items: Vec::new(),
                };
                for address in &chain.instructions {
                    let Some(instruction) = disasm.instruction_at(*address) else {
                        continue;
                    };
                    let (mnemonic, operands, registers) = text(*address).unwrap_or_else(|| {
                        (
                            format!("op{:x}", instruction.mnemonic),
                            String::new(),
                            Vec::new(),
                        )
                    });
                    let mut defines = Vec::new();
                    let mut uses = Vec::new();
                    for use_ in &instruction.register_uses {
                        let name = register_name(use_.register);
                        match use_.access {
                            Access::Read => push_once(&mut uses, name),
                            // A write of 32 bits or more replaces the whole
                            // register; a narrower one keeps the rest of it,
                            // so it reads the old version too.
                            Access::Write if use_.register.bit_size >= 32 => {
                                push_once(&mut defines, name)
                            }
                            _ => {
                                push_once(&mut uses, name.clone());
                                push_once(&mut defines, name);
                            }
                        }
                    }
                    let flow = flow_text(&instruction.flow);
                    let text = if operands.is_empty() {
                        format!("{mnemonic}{flow}")
                    } else {
                        format!("{mnemonic} {operands}{flow}")
                    };
                    // The registers as the text spells them, typed by the
                    // width each spelling names: `eax: int`, `rax: long`.
                    let types: Vec<(String, String)> = registers
                        .iter()
                        .filter_map(|register| {
                            register_width(register).map(|bits| {
                                (register.clone(), crate::lift::type_name(bits).to_string())
                            })
                        })
                        .collect();
                    let names = |bits: u32| -> Vec<String> {
                        crate::cpu_context::flag_names(bits)
                            .into_iter()
                            .map(str::to_string)
                            .collect()
                    };
                    push_item(
                        &mut function,
                        &mut block,
                        IlItem {
                            id: 0,
                            block: index,
                            depth: 0,
                            addresses: vec![*address],
                            text,
                            defines,
                            uses,
                            phi: false,
                            opcode: crate::cpu_context::opcode_name(instruction.opcode),
                            flags_read: names(instruction.flags_read),
                            flags_written: names(instruction.flags_written),
                            types,
                            ..Default::default()
                        },
                    );
                }
                function.blocks.push(block);
            }
        }
        Level::Low => {
            for (index, statements) in stages.low.iter().enumerate() {
                let Some(chain) = stages.chains.get(index) else {
                    break;
                };
                let mut block = IlBlock {
                    id: index,
                    address: chain.address,
                    successors: chain.successors.clone(),
                    items: Vec::new(),
                };
                for statement in statements {
                    push_item(
                        &mut function,
                        &mut block,
                        IlItem {
                            id: 0,
                            block: index,
                            depth: 0,
                            addresses: statement.addresses.clone(),
                            text: if casts {
                                statement.casts.clone()
                            } else {
                                statement.text.clone()
                            },
                            defines: statement.defines.clone(),
                            uses: statement.uses.clone(),
                            phi: false,
                            opcode: Some(statement.kind.to_string()),
                            ..Default::default()
                        },
                    );
                }
                function.blocks.push(block);
            }
        }
        Level::Medium => {
            for (index, node) in stages.medium.iter().enumerate() {
                let mut block = IlBlock {
                    id: index,
                    address: node.address,
                    successors: node.terminator.successors(),
                    items: Vec::new(),
                };
                for statement in &node.statements {
                    let (defines, uses) = defines_and_uses(&statement.node);
                    push_item(
                        &mut function,
                        &mut block,
                        IlItem {
                            id: 0,
                            block: index,
                            depth: 0,
                            addresses: statement.addresses.clone(),
                            text: line(&maybe_casts(&statement.node, casts)),
                            defines,
                            uses,
                            phi: false,
                            opcode: Some(node_kind(&statement.node).to_string()),
                            ..Default::default()
                        },
                    );
                }
                let end = match &node.terminator {
                    Terminator::Return => None,
                    Terminator::Goto { target, addresses } => {
                        stages.medium.get(*target).map(|to| {
                            (
                                "goto",
                                format!("goto block_{:x}", to.address),
                                addresses.clone(),
                                Vec::new(),
                            )
                        })
                    }
                    Terminator::Branch {
                        cond,
                        taken,
                        next,
                        addresses,
                    } => Some((
                        "branch",
                        format!(
                            "if ({}) goto block_{:x} else goto block_{:x}",
                            line(&maybe_casts(cond, casts)),
                            stages.medium.get(*taken).map_or(0, |to| to.address),
                            stages.medium.get(*next).map_or(0, |to| to.address)
                        ),
                        addresses.clone(),
                        names_in(cond),
                    )),
                    Terminator::Switch {
                        index: switched,
                        cases,
                        addresses,
                    } => Some((
                        "switch",
                        format!(
                            "switch ({}) {}",
                            line(&maybe_casts(switched, casts)),
                            cases
                                .iter()
                                .map(|(values, to)| format!(
                                    "{} -> block_{:x}",
                                    values
                                        .iter()
                                        .map(|value| value.to_string())
                                        .collect::<Vec<_>>()
                                        .join(","),
                                    stages.medium.get(*to).map_or(0, |to| to.address)
                                ))
                                .collect::<Vec<_>>()
                                .join("; ")
                        ),
                        addresses.clone(),
                        names_in(switched),
                    )),
                };
                if let Some((kind, text, addresses, uses)) = end {
                    // A fall-through has no jump of its own: it is the last
                    // instruction's, so the item still maps onto the listing.
                    let addresses = if addresses.is_empty() {
                        stages
                            .chains
                            .iter()
                            .find(|chain| chain.address == node.address)
                            .and_then(|chain| chain.instructions.last().copied())
                            .map(|address| vec![address])
                            .or_else(|| {
                                node.statements
                                    .last()
                                    .map(|statement| statement.addresses.clone())
                            })
                            .unwrap_or_default()
                    } else {
                        addresses
                    };
                    push_item(
                        &mut function,
                        &mut block,
                        IlItem {
                            id: 0,
                            block: index,
                            depth: 0,
                            addresses,
                            text,
                            defines: Vec::new(),
                            uses,
                            phi: false,
                            opcode: Some(kind.to_string()),
                            ..Default::default()
                        },
                    );
                }
                function.blocks.push(block);
            }
        }
        Level::High => {
            let mut block = IlBlock {
                id: 0,
                address: stages.function.address,
                successors: Vec::new(),
                items: Vec::new(),
            };
            high_items(&stages.high, 0, &mut function, &mut block, casts);
            function.blocks.push(block);
        }
    }
    decorate(&mut function, stages);
    function
}

fn push_once(names: &mut Vec<String>, name: String) {
    if !names.contains(&name) {
        names.push(name);
    }
}

fn push_item(function: &mut IlFunction, block: &mut IlBlock, mut item: IlItem) -> usize {
    item.id = function.items.len();
    block.items.push(item.id);
    function.items.push(item);
    function.items.len() - 1
}

/// Where an instruction's flow goes, as a note after it.
fn flow_text(flow: &Flow) -> String {
    match flow {
        Flow::Next => String::new(),
        Flow::UnconditionalBranch(target) => format!("  ; jump {target:#x}"),
        Flow::ConditionalBranch(target) => format!("  ; branch {target:#x}"),
        Flow::IndirectBranch => "  ; jump indirect".to_string(),
        Flow::Call(target) => format!("  ; call {target:#x}"),
        Flow::IndirectCall => "  ; call indirect".to_string(),
        Flow::Return => "  ; return".to_string(),
        Flow::Interrupt => "  ; interrupt".to_string(),
        Flow::Syscall => "  ; syscall".to_string(),
        Flow::Trap => "  ; trap".to_string(),
        Flow::Halt => "  ; halt".to_string(),
        Flow::Xbegin(target) => format!("  ; transaction, abort to {target:#x}"),
        Flow::Invalid => "  ; invalid".to_string(),
    }
}

/// The structured body as items, each at its depth.
fn high_items(
    statements: &[Statement],
    depth: usize,
    function: &mut IlFunction,
    block: &mut IlBlock,
    casts: bool,
) {
    for statement in statements {
        let (defines, uses) = defines_and_uses(&statement.node);
        let node = maybe_casts(&statement.node, casts);
        let item = |kind: &str, text: String, defines: Vec<String>, uses: Vec<String>| IlItem {
            id: 0,
            block: 0,
            depth,
            addresses: statement.addresses.clone(),
            text,
            defines,
            uses,
            phi: false,
            opcode: Some(kind.to_string()),
            ..Default::default()
        };
        match &statement.kind {
            StatementKind::Plain => {
                push_item(
                    function,
                    block,
                    item(node_kind(&statement.node), line(&node), defines, uses),
                );
            }
            StatementKind::If {
                then_part,
                else_part,
            } => {
                push_item(
                    function,
                    block,
                    item("if", format!("if ({})", line(&node)), Vec::new(), uses),
                );
                high_items(then_part, depth + 1, function, block, casts);
                if !else_part.is_empty() {
                    push_item(
                        function,
                        block,
                        item("else", "else".to_string(), Vec::new(), Vec::new()),
                    );
                    high_items(else_part, depth + 1, function, block, casts);
                }
            }
            StatementKind::While { body } => {
                push_item(
                    function,
                    block,
                    item(
                        "while",
                        format!("while ({})", line(&node)),
                        Vec::new(),
                        uses,
                    ),
                );
                high_items(body, depth + 1, function, block, casts);
            }
            StatementKind::DoWhile { body } => {
                push_item(
                    function,
                    block,
                    item("do", "do".to_string(), Vec::new(), Vec::new()),
                );
                high_items(body, depth + 1, function, block, casts);
                push_item(
                    function,
                    block,
                    item(
                        "while",
                        format!("while ({})", line(&node)),
                        Vec::new(),
                        uses,
                    ),
                );
            }
            StatementKind::For { init, step, body } => {
                let (init_defines, mut init_uses) = defines_and_uses(&init.node);
                let (step_defines, step_uses) = defines_and_uses(&step.node);
                for name in uses.iter().chain(&step_uses) {
                    push_once(&mut init_uses, name.clone());
                }
                let mut defines = init_defines;
                for name in step_defines {
                    push_once(&mut defines, name);
                }
                push_item(
                    function,
                    block,
                    item(
                        "for",
                        format!(
                            "for ({}; {}; {})",
                            line(&maybe_casts(&init.node, casts)),
                            line(&node),
                            line(&maybe_casts(&step.node, casts))
                        ),
                        defines,
                        init_uses,
                    ),
                );
                high_items(body, depth + 1, function, block, casts);
            }
            StatementKind::Switch { arms } => {
                push_item(
                    function,
                    block,
                    item(
                        "switch",
                        format!("switch ({})", line(&node)),
                        Vec::new(),
                        uses,
                    ),
                );
                for arm in arms {
                    let labels: Vec<String> =
                        arm.values.iter().map(|v| format!("case {v}")).collect();
                    push_item(
                        function,
                        block,
                        IlItem {
                            id: 0,
                            block: 0,
                            depth: depth + 1,
                            addresses: statement.addresses.clone(),
                            text: format!("{}:", labels.join(": ")),
                            defines: Vec::new(),
                            uses: Vec::new(),
                            phi: false,
                            opcode: Some("case".to_string()),
                            ..Default::default()
                        },
                    );
                    high_items(&arm.body, depth + 2, function, block, casts);
                }
            }
        }
    }
}

/// The items of `from` and the items of `to` that share an address with
/// each, by id: how one level maps onto another.
pub fn correspondence(from: &IlFunction, to: &IlFunction) -> Vec<(usize, Vec<usize>)> {
    let mut by_address: HashMap<u64, Vec<usize>> = HashMap::new();
    for item in &to.items {
        for address in &item.addresses {
            by_address.entry(*address).or_default().push(item.id);
        }
    }
    from.items
        .iter()
        .map(|item| {
            let mut found: Vec<usize> = item
                .addresses
                .iter()
                .flat_map(|address| by_address.get(address).into_iter().flatten().copied())
                .collect();
            found.sort_unstable();
            found.dedup();
            (item.id, found)
        })
        .collect()
}

/// The function in static single assignment form: every definition
/// versioned, a φ item at the start of each block where paths carrying
/// different versions meet, by the dominance frontiers of the block graph.
/// A name read before any definition is version `#0`. The high level has no
/// graph of its own: it takes the versions of the medium level it was
/// built from, by the statements the two share, and keeps `ssa: false`
/// when none is given. A block the entry does not reach keeps its names
/// plain. The φ items are appended after the function's own, so their ids
/// follow the last item's rather than their block's.
pub fn to_ssa(
    function: &IlFunction,
    analysis: &Analysis,
    medium: Option<&IlFunction>,
) -> IlFunction {
    let mut out = function.clone();
    if function.level == Level::High {
        if let Some(medium) = medium {
            project_versions(&mut out, medium);
            out.ssa = true;
        }
        return out;
    }
    out.ssa = true;
    let count = out.blocks.len();
    if count == 0 || analysis.idom.len() < count || analysis.preds.len() < count {
        return out;
    }
    let reachable =
        |block: usize| analysis.order.get(block).copied().unwrap_or(usize::MAX) != usize::MAX;
    // The entry: its own immediate dominator. A virtual start block stands
    // above it, so an entry that is also a loop header is a join of the way
    // in and the way back.
    let Some(entry) = (0..count).find(|block| analysis.idom.get(*block) == Some(&Some(*block)))
    else {
        return out;
    };
    // The dominance frontiers.
    let mut frontiers: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); count];
    for block in 0..count {
        if !reachable(block) {
            continue;
        }
        let preds: BTreeSet<usize> = analysis.preds[block]
            .iter()
            .copied()
            .filter(|pred| reachable(*pred))
            .collect();
        if preds.len() + usize::from(block == entry) < 2 {
            continue;
        }
        // The walk from a predecessor stops under the block's dominator;
        // for the entry that is the virtual start, above everything.
        let stop = (block != entry)
            .then(|| analysis.idom.get(block).copied().flatten())
            .flatten();
        for pred in preds {
            let mut runner = pred;
            let mut steps = 0;
            while Some(runner) != stop && steps <= count && runner < count {
                frontiers[runner].insert(block);
                if runner == entry {
                    break;
                }
                match analysis.idom.get(runner) {
                    Some(Some(next)) if *next != runner => runner = *next,
                    _ => break,
                }
                steps += 1;
            }
        }
    }
    // Where each name is defined, and the φs it needs.
    let mut defined_in: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for item in &out.items {
        for name in &item.defines {
            defined_in
                .entry(name.clone())
                .or_default()
                .insert(item.block);
        }
    }
    let mut phis: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    for (name, blocks) in &defined_in {
        let mut work: Vec<usize> = blocks.iter().copied().collect();
        let mut placed: BTreeSet<usize> = BTreeSet::new();
        let mut seen: BTreeSet<usize> = blocks.clone();
        while let Some(block) = work.pop() {
            for frontier in &frontiers[block] {
                if placed.insert(*frontier) {
                    phis.entry(*frontier).or_default().insert(name.clone());
                    if seen.insert(*frontier) {
                        work.push(*frontier);
                    }
                }
            }
        }
    }
    // The φ items, at the start of their blocks, their operands filled as
    // the renaming reaches each predecessor.
    let mut phi_items: Vec<Vec<(String, usize)>> = vec![Vec::new(); count];
    for (block, names) in &phis {
        let mut ids = Vec::new();
        for name in names {
            let id = out.items.len();
            let address = out.blocks[*block].address;
            let types = out
                .items
                .iter()
                .flat_map(|item| &item.types)
                .find(|(known, _)| known == name)
                .cloned()
                .into_iter()
                .collect();
            let stack_pointer = out.blocks[*block]
                .items
                .first()
                .and_then(|first| out.items[*first].stack_pointer);
            out.items.push(IlItem {
                id,
                block: *block,
                depth: 0,
                addresses: vec![address],
                text: String::new(),
                defines: vec![name.clone()],
                uses: Vec::new(),
                phi: true,
                opcode: Some("phi".to_string()),
                types,
                stack_pointer,
                ..Default::default()
            });
            phi_items[*block].push((name.clone(), id));
            ids.push(id);
        }
        ids.append(&mut out.blocks[*block].items);
        out.blocks[*block].items = ids;
    }
    // Renaming, down the dominator tree. A φ at the entry has the version
    // that came in from outside the function.
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); count];
    for block in 0..count {
        if let Some(Some(idom)) = analysis.idom.get(block) {
            if *idom != block {
                children[*idom].push(block);
            }
        }
    }
    let mut counters: BTreeMap<String, usize> = BTreeMap::new();
    let mut stacks: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut phi_operands: BTreeMap<usize, Vec<(Option<usize>, String)>> = BTreeMap::new();
    for (name, id) in &phi_items[entry] {
        phi_operands
            .entry(*id)
            .or_default()
            .push((None, format!("{name}#0")));
    }
    rename(
        entry,
        &children,
        &mut out,
        &phi_items,
        &mut counters,
        &mut stacks,
        &mut phi_operands,
        0,
    );
    for (id, mut operands) in phi_operands {
        operands.sort_by_key(|(block, _)| block.map_or(0, |block| block + 1));
        out.items[id].uses = operands
            .iter()
            .map(|(_, version)| version.clone())
            .collect();
        out.items[id].text = format!(
            "{} = φ({})",
            out.items[id].defines[0],
            operands
                .iter()
                .map(|(block, version)| match block {
                    Some(block) => format!("{version} from block_{:x}", out.blocks[*block].address),
                    None => format!("{version} from entry"),
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn rename(
    block: usize,
    children: &[Vec<usize>],
    function: &mut IlFunction,
    phi_items: &[Vec<(String, usize)>],
    counters: &mut BTreeMap<String, usize>,
    stacks: &mut BTreeMap<String, Vec<usize>>,
    phi_operands: &mut BTreeMap<usize, Vec<(Option<usize>, String)>>,
    depth: usize,
) {
    if depth > function.blocks.len() + 1 {
        return;
    }
    let mut pushed: Vec<String> = Vec::new();
    let item_ids = function.blocks[block].items.clone();
    for id in item_ids {
        let item = &mut function.items[id];
        if !item.phi {
            item.uses = item
                .uses
                .iter()
                .map(|name| {
                    let version = stacks
                        .get(name)
                        .and_then(|stack| stack.last())
                        .copied()
                        .unwrap_or(0);
                    format!("{name}#{version}")
                })
                .collect();
        }
        item.defines = item
            .defines
            .iter()
            .map(|name| {
                let counter = counters.entry(name.clone()).or_insert(0);
                *counter += 1;
                stacks.entry(name.clone()).or_default().push(*counter);
                pushed.push(name.clone());
                format!("{name}#{counter}")
            })
            .collect();
        if !item.phi {
            item.text = versioned_text(&item.text, &item.defines, &item.uses);
        }
    }
    // The φs of the successors take this block's versions, once per edge.
    let successors: BTreeSet<usize> = function.blocks[block].successors.iter().copied().collect();
    for successor in successors {
        for (name, id) in phi_items.get(successor).into_iter().flatten() {
            let version = stacks
                .get(name)
                .and_then(|stack| stack.last())
                .copied()
                .unwrap_or(0);
            phi_operands
                .entry(*id)
                .or_default()
                .push((Some(block), format!("{name}#{version}")));
        }
    }
    for child in &children[block] {
        rename(
            *child,
            children,
            function,
            phi_items,
            counters,
            stacks,
            phi_operands,
            depth + 1,
        );
    }
    for name in pushed {
        if let Some(stack) = stacks.get_mut(&name) {
            stack.pop();
        }
    }
}

/// The item's text with its names versioned: each whole-word name replaced
/// by its version, the definition's on the left of `=`, the uses' on the
/// right, so `x = x + 1` reads `x#2 = x#1 + 1`.
fn versioned_text(text: &str, defines: &[String], uses: &[String]) -> String {
    let split = |versioned: &String| -> Option<(String, String)> {
        versioned
            .rsplit_once('#')
            .map(|(name, version)| (name.to_string(), format!("{name}#{version}")))
    };
    // An item that is not an assignment — a machine instruction, whose
    // registers the text spells its own way — keeps its text and says what
    // it writes beside it.
    let Some((left, right)) = text.split_once(" = ").filter(|_| !defines.is_empty()) else {
        if defines.is_empty() {
            let mut right = text.to_string();
            for versioned in uses {
                if let Some((name, with)) = split(versioned) {
                    right = replace_word(&right, &name, &with);
                }
            }
            return right;
        }
        if text.contains("  ; ") {
            return format!("{text}, writes {}", defines.join(", "));
        }
        return format!("{text}  ; writes {}", defines.join(", "));
    };
    let (left, right) = (left.to_string(), right.to_string());
    let mut right = right;
    for versioned in uses {
        if let Some((name, with)) = split(versioned) {
            right = replace_word(&right, &name, &with);
        }
    }
    let mut left = left;
    for versioned in defines {
        if let Some((name, with)) = split(versioned) {
            left = replace_word(&left, &name, &with);
        }
    }
    format!("{left} = {right}")
}

/// `text` with every whole-word `word` replaced by `with`, outside string
/// literals; a field (`.a`, `->a`) is not the variable of that name.
fn replace_word(text: &str, word: &str, with: &str) -> String {
    if word.is_empty() {
        return text.to_string();
    }
    let is_ident = |c: char| c.is_alphanumeric() || c == '_' || c == '#';
    let mut out = String::new();
    for (quoted, span) in spans(text) {
        if quoted {
            out.push_str(span);
            continue;
        }
        let mut rest = span;
        while let Some(at) = rest.find(word) {
            // The character before the match may have been written already.
            let before = rest[..at]
                .chars()
                .next_back()
                .or_else(|| out.chars().next_back());
            let field = before == Some('.')
                || (before == Some('>') && {
                    let written = format!("{out}{}", &rest[..at]);
                    written.ends_with("->")
                });
            let after = rest[at + word.len()..].chars().next();
            let whole = !before.is_some_and(is_ident)
                && !field
                && !after.is_some_and(|c| is_ident(c) && c != '#')
                && after != Some('#');
            out.push_str(&rest[..at]);
            if whole {
                out.push_str(with);
            } else {
                out.push_str(word);
            }
            rest = &rest[at + word.len()..];
        }
        out.push_str(rest);
    }
    out
}

/// The text cut into the spans that are string literals or `/* … */`
/// comments — protected, no name in them is a variable — and the spans
/// between them, in order, each flagged.
fn spans(text: &str) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut comment = false;
    let mut escaped = false;
    let mut previous = None;
    for (at, c) in text.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                out.push((true, &text[start..at + 1]));
                start = at + 1;
                quoted = false;
            }
        } else if comment {
            if c == '/' && previous == Some('*') && at > start + 2 {
                out.push((true, &text[start..at + 1]));
                start = at + 1;
                comment = false;
            }
        } else if c == '"' || (c == '*' && previous == Some('/')) {
            let open = if c == '"' { at } else { at - 1 };
            if open > start {
                out.push((false, &text[start..open]));
            }
            start = open;
            quoted = c == '"';
            comment = !quoted;
        }
        previous = Some(c);
    }
    if start < text.len() {
        out.push((quoted || comment, &text[start..]));
    }
    out
}

/// Give the high level the versions of the medium level: an item takes
/// the names of the medium item with the same addresses and text, and a
/// control header — `if (…)`, `while (…)`, `switch (…)`, `for (…; …; …)`,
/// whose text the medium level never has whole — takes them part by part
/// from the medium items that share its addresses: an assignment from the
/// statement it is, a condition from the branch that tests it.
fn project_versions(high: &mut IlFunction, medium: &IlFunction) {
    let stripped: Vec<String> = medium
        .items
        .iter()
        .map(|item| strip_versions(&item.text))
        .collect();
    for item in &mut high.items {
        let found = medium.items.iter().enumerate().find(|(index, candidate)| {
            !candidate.phi && candidate.addresses == item.addresses && stripped[*index] == item.text
        });
        if let Some((_, found)) = found {
            item.defines = found.defines.clone();
            item.uses = found.uses.clone();
            item.text = found.text.clone();
            continue;
        }
        // A header: its parts inside the parentheses.
        let Some((keyword, parts)) = header_parts(&item.text) else {
            continue;
        };
        let shared: Vec<(usize, &IlItem)> = medium
            .items
            .iter()
            .enumerate()
            .filter(|(_, candidate)| {
                !candidate.phi
                    && candidate
                        .addresses
                        .iter()
                        .any(|address| item.addresses.contains(address))
            })
            .collect();
        if shared.is_empty() {
            continue;
        }
        let mut defines = Vec::new();
        let mut uses = Vec::new();
        let mut versioned = Vec::new();
        for part in &parts {
            // The statement the part is, versions and all.
            if let Some((_, found)) = shared.iter().find(|(index, _)| stripped[*index] == *part) {
                for name in &found.defines {
                    push_once(&mut defines, name.clone());
                }
                for name in &found.uses {
                    push_once(&mut uses, name.clone());
                }
                versioned.push(found.text.clone());
                continue;
            }
            // A condition: the branch that tests it names what it reads.
            // The names the header itself reads: not a cast's type, a
            // callee, or a field.
            let names: Vec<String> = names_of(part)
                .into_iter()
                .filter(|name| item.uses.contains(name))
                .collect();
            let tester = shared.iter().find(|(_, candidate)| {
                candidate.defines.is_empty()
                    && (candidate.text.starts_with("if (")
                        || candidate.text.starts_with("switch ("))
                    && names
                        .iter()
                        .all(|name| candidate.uses.iter().any(|use_| base(use_) == name))
            });
            match tester {
                Some((_, found)) => {
                    for name in &found.uses {
                        if names.contains(&base(name).to_string()) {
                            push_once(&mut uses, name.clone());
                        }
                    }
                    versioned.push(versioned_text(part, &[], &found.uses));
                }
                None => versioned.push(part.to_string()),
            }
        }
        if versioned.iter().any(|part| part.contains('#')) {
            item.text = format!("{keyword} ({})", versioned.join("; "));
            item.defines = defines;
            item.uses = uses;
        }
    }
}

/// A header's keyword and the parts inside its parentheses: one for
/// `if`, `while` and `switch`, three for `for`.
fn header_parts(text: &str) -> Option<(&str, Vec<&str>)> {
    let keyword = ["if", "while", "switch", "for"]
        .into_iter()
        .find(|keyword| text.starts_with(&format!("{keyword} (")))?;
    let inside = text
        .strip_prefix(keyword)?
        .strip_prefix(" (")?
        .strip_suffix(')')?;
    Some(if keyword == "for" {
        (keyword, split_outside_literals(inside, "; "))
    } else {
        (keyword, vec![inside])
    })
}

/// `text` split at each `separator` outside its string literals.
fn split_outside_literals<'a>(text: &'a str, separator: &str) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut at = 0;
    for (protected, span) in spans(text) {
        if !protected {
            let mut rest = 0;
            while let Some(found) = span[rest..].find(separator) {
                parts.push(&text[start..at + rest + found]);
                rest += found + separator.len();
                start = at + rest;
            }
        }
        at += span.len();
    }
    parts.push(&text[start..]);
    parts
}

/// The identifiers in a piece of text, outside its string literals.
fn names_of(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for (quoted, span) in spans(text) {
        if quoted {
            continue;
        }
        // A field is not a name, whichever way it is reached.
        let span = span.replace("->", "..");
        let mut word = String::new();
        let mut previous = None;
        for c in span.chars() {
            if c.is_alphanumeric() || c == '_' {
                word.push(c);
            } else {
                if !word.is_empty()
                    && !word.starts_with(|c: char| c.is_ascii_digit())
                    && previous != Some('.')
                {
                    push_once(&mut names, std::mem::take(&mut word));
                }
                word.clear();
                previous = Some(c);
            }
        }
        if !word.is_empty()
            && !word.starts_with(|c: char| c.is_ascii_digit())
            && previous != Some('.')
        {
            push_once(&mut names, word);
        }
    }
    names
}

/// A versioned name's name: `x` of `x#2`.
fn base(versioned: &str) -> &str {
    versioned
        .rsplit_once('#')
        .map_or(versioned, |(name, _)| name)
}

/// Text with the versions taken off: `x#2` is `x`.
fn strip_versions(text: &str) -> String {
    let mut out = String::new();
    for (quoted, span) in spans(text) {
        if quoted {
            out.push_str(span);
            continue;
        }
        let mut chars = span.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '#' && chars.peek().is_some_and(|d| d.is_ascii_digit()) {
                while chars.peek().is_some_and(|d| d.is_ascii_digit()) {
                    chars.next();
                }
            } else {
                out.push(c);
            }
        }
    }
    out
}

/// The instruction at `address` in a disassembly, for callers that hold
/// one.
pub fn instruction_at(disasm: &Disasm, address: u64) -> Option<&DecodedInsn> {
    disasm.instruction_at(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_versioned_whole_and_versions_strip_back() {
        assert_eq!(replace_word("x = x + 1", "x", "x#1"), "x#1 = x#1 + 1");
        assert_eq!(replace_word("xx + x_1 + x", "x", "x#3"), "xx + x_1 + x#3");
        assert_eq!(
            versioned_text(
                "x = x + y",
                &["x#2".to_string()],
                &["x#1".to_string(), "y#1".to_string()]
            ),
            "x#2 = x#1 + y#1"
        );
        assert_eq!(
            versioned_text("*p = q", &[], &["p#1".to_string(), "q#1".to_string()]),
            "*p#1 = q#1"
        );
        assert_eq!(
            versioned_text(
                "mov rbp,rsp",
                &["r1_5#2".to_string()],
                &["r1_4#1".to_string()]
            ),
            "mov rbp,rsp  ; writes r1_5#2"
        );
        assert_eq!(strip_versions("x#12 = y#3 + 1"), "x = y + 1");
        assert_eq!(Level::parse("Medium"), Some(Level::Medium));
        assert_eq!(Level::parse("mlil"), None);
        assert_eq!(Level::parse("nope"), None);
        assert_eq!(
            versioned_text("ret  ; return", &["r1_4#3".to_string()], &[]),
            "ret  ; return, writes r1_4#3"
        );
    }

    #[test]
    fn string_literals_and_fields_are_left_alone() {
        assert_eq!(
            replace_word("printf(\"a = %d\\n\", a)", "a", "a#0"),
            "printf(\"a = %d\\n\", a#0)"
        );
        assert_eq!(
            replace_word("f(\"\\\"a\", a) + a", "a", "a#2"),
            "f(\"\\\"a\", a#2) + a#2"
        );
        assert_eq!(
            replace_word("p->a + s.a + a", "a", "a#1"),
            "p->a + s.a + a#1"
        );
        assert_eq!(replace_word("b > a", "a", "a#1"), "b > a#1");
        assert_eq!(strip_versions("f(\"#1\", x#1)"), "f(\"#1\", x)");
        assert_eq!(
            replace_word("x = unknown /* a after the call */ + a", "a", "a#0"),
            "x = unknown /* a after the call */ + a#0"
        );
        assert_eq!(names_of("p->next"), vec!["p"]);
        assert_eq!(names_of("(long)i < n"), vec!["long", "i", "n"]);
        assert_eq!(
            split_outside_literals("x = f(\"a; b\"); y = 1; z", "; "),
            vec!["x = f(\"a; b\")", "y = 1", "z"]
        );
        assert_eq!(names_of("p->a + s.a + a * 10 + \"b\""), vec!["p", "s", "a"]);
    }

    #[test]
    fn the_render_options_decorate_an_item_and_casts_spell_every_constant() {
        let item = IlItem {
            text: "local_14 = local_14 + 1".to_string(),
            opcode: Some("assign".to_string()),
            stack_pointer: Some(-0x20),
            types: vec![("local_14".to_string(), "int".to_string())],
            ..Default::default()
        };
        let function = IlFunction {
            name: "f".to_string(),
            address: 0,
            level: Level::Medium,
            ssa: false,
            blocks: Vec::new(),
            items: Vec::new(),
        };
        assert_eq!(
            function.item_text(&item, &Render::default()),
            "local_14 = local_14 + 1"
        );
        assert_eq!(
            function.item_text(&item, &Render::ALL),
            "[assign] local_14 = local_14 + 1  ; sp = entry-0x20  ; types: local_14: int"
        );
        let lifted = IlItem {
            text: "cmp eax,[rbp-14h]".to_string(),
            opcode: Some("Cmp_r32_rm32".to_string()),
            flags_written: vec!["CF".to_string(), "ZF".to_string()],
            stack_pointer: Some(0),
            ..Default::default()
        };
        assert_eq!(
            function.item_text(
                &lifted,
                &Render {
                    flags: true,
                    stack_pointer: true,
                    ..Render::default()
                }
            ),
            "cmp eax,[rbp-14h]  ; sp = entry  ; flags: reads none, writes CF ZF"
        );
        assert_eq!(offset_text(8), "+0x8");
        let node = AstNode::Assign {
            lhs: Box::new(AstNode::var("x")),
            rhs: Box::new(AstNode::binary(
                AstNode::constant(1, 4),
                crate::ast::BinaryOp::Add,
                AstNode::Cast {
                    ty: "long".to_string(),
                    target: Box::new(AstNode::constant(2, 4)),
                },
            )),
        };
        assert_eq!(line(&with_casts(&node)), "x = (int)1 + (long)2");
        assert_eq!(line(&node), "x = 1 + (long)2");
        assert_eq!(node_kind(&node), "assign");
        let mut types = BTreeMap::new();
        types.insert("x".to_string(), "int".to_string());
        assert_eq!(type_of("x#3", &types).as_deref(), Some("int"));
        assert_eq!(type_of("entry5", &types).as_deref(), Some("long"));
        assert_eq!(type_of("r1_0", &types), None);
        assert_eq!(register_width("eax"), Some(32));
        assert_eq!(register_width("RBP"), Some(64));
        assert_eq!(register_width("ax"), Some(16));
        assert_eq!(register_width("al"), Some(8));
        assert_eq!(register_width("r8d"), Some(32));
        assert_eq!(register_width("r15"), Some(64));
        assert_eq!(register_width("r9b"), Some(8));
        assert_eq!(register_width("xmm0"), None);
        assert_eq!(register_width("r16"), None);
        let sum = AstNode::binary(
            AstNode::var("x"),
            crate::ast::BinaryOp::Add,
            AstNode::constant(8, 4),
        );
        assert_eq!(line(&cast_to("int", &sum)), "(int)(x + (int)8)");
        assert_eq!(line(&cast_to("long", &AstNode::constant(0, 4))), "(long)0");
        assert_eq!(
            line(&cast_to(
                "long",
                &AstNode::Cast {
                    ty: "long".to_string(),
                    target: Box::new(AstNode::var("y"))
                }
            )),
            "(long)y"
        );
    }

    /// A statement for a test: its text, what it defines, what it uses.
    type Statement<'a> = (&'a str, &'a [&'a str], &'a [&'a str]);

    /// A function over a block graph: each block its statements and its
    /// successors.
    fn function_over(blocks: &[(&[Statement], &[usize])]) -> (IlFunction, Analysis) {
        let mut function = IlFunction {
            name: "f".to_string(),
            address: 0x1000,
            level: Level::Medium,
            ssa: false,
            blocks: Vec::new(),
            items: Vec::new(),
        };
        for (index, (statements, successors)) in blocks.iter().enumerate() {
            let mut block = IlBlock {
                id: index,
                address: 0x1000 + index as u64 * 0x10,
                successors: successors.to_vec(),
                items: Vec::new(),
            };
            let base = block.address;
            for (at, (text, defines, uses)) in statements.iter().enumerate() {
                push_item(
                    &mut function,
                    &mut block,
                    IlItem {
                        id: 0,
                        block: index,
                        depth: 0,
                        addresses: vec![base + at as u64],
                        text: text.to_string(),
                        defines: defines.iter().map(|d| d.to_string()).collect(),
                        uses: uses.iter().map(|u| u.to_string()).collect(),
                        phi: false,
                        ..Default::default()
                    },
                );
            }
            function.blocks.push(block);
        }
        let successors: Vec<Vec<usize>> = blocks.iter().map(|(_, s)| s.to_vec()).collect();
        let analysis =
            crate::structure::analyze(&successors, 0, |node| 0x1000 + node as u64 * 0x10)
                .expect("reducible");
        (function, analysis)
    }

    #[test]
    fn a_diamond_meets_in_one_phi_with_an_operand_per_path() {
        let (function, analysis) = function_over(&[
            (&[("x = 1", &["x"], &[])], &[1, 2]),
            (&[("x = 2", &["x"], &[])], &[3]),
            (&[("x = 3", &["x"], &[])], &[3]),
            (&[("y = x", &["y"], &["x"])], &[]),
        ]);
        let ssa = to_ssa(&function, &analysis, None);
        let text = ssa.text();
        assert!(text.contains("x#1 = 1"), "{text}");
        assert!(text.contains("x#2 = 2"), "{text}");
        assert!(text.contains("x#3 = 3"), "{text}");
        assert!(
            text.contains("x#4 = φ(x#2 from block_1010, x#3 from block_1020)"),
            "{text}"
        );
        assert!(text.contains("y#1 = x#4"), "{text}");
        let phis: Vec<&IlItem> = ssa.items.iter().filter(|item| item.phi).collect();
        assert_eq!(phis.len(), 1);
        assert_eq!(phis[0].block, 3);
        assert_eq!(ssa.blocks[3].items[0], phis[0].id);
        // The φ item's id follows the function's own items.
        assert_eq!(phis[0].id, 4);
    }

    #[test]
    fn an_entry_that_is_a_loop_header_gets_a_phi_with_the_way_in() {
        let (function, analysis) = function_over(&[
            (&[("x = x + 1", &["x"], &["x"])], &[0, 1]),
            (&[("return x", &[], &["x"])], &[]),
        ]);
        let ssa = to_ssa(&function, &analysis, None);
        let text = ssa.text();
        assert!(
            text.contains("x#1 = φ(x#0 from entry, x#2 from block_1000)"),
            "{text}"
        );
        assert!(text.contains("x#2 = x#1 + 1"), "{text}");
        assert!(text.contains("return x#2"), "{text}");
        // A branch to one block by two edges gives the φ one operand.
        let (function, analysis) = function_over(&[
            (&[("x = 1", &["x"], &[])], &[1, 1]),
            (&[("x = 2", &["x"], &[])], &[1, 2]),
            (&[("return x", &[], &["x"])], &[]),
        ]);
        let ssa = to_ssa(&function, &analysis, None);
        let text = ssa.text();
        assert!(
            text.contains("x#2 = φ(x#1 from block_1000, x#3 from block_1010)"),
            "{text}"
        );
    }

    #[test]
    fn high_level_headers_take_their_versions_from_the_medium_level() {
        let mut medium = IlFunction {
            name: "f".to_string(),
            address: 0x10,
            level: Level::Medium,
            ssa: true,
            blocks: Vec::new(),
            items: Vec::new(),
        };
        let mut block = IlBlock {
            id: 0,
            address: 0x10,
            successors: Vec::new(),
            items: Vec::new(),
        };
        let item = |addresses: &[u64], text: &str, defines: &[&str], uses: &[&str]| IlItem {
            id: 0,
            block: 0,
            depth: 0,
            addresses: addresses.to_vec(),
            text: text.to_string(),
            defines: defines.iter().map(|d| d.to_string()).collect(),
            uses: uses.iter().map(|u| u.to_string()).collect(),
            phi: false,
            ..Default::default()
        };
        push_item(
            &mut medium,
            &mut block,
            item(&[0x10], "x#1 = 1", &["x#1"], &[]),
        );
        push_item(
            &mut medium,
            &mut block,
            item(
                &[0x14],
                "if (x#2 <= a#0 + p#0->a) goto block_20 else goto block_30",
                &[],
                &["x#2", "a#0", "p#0"],
            ),
        );
        push_item(
            &mut medium,
            &mut block,
            item(&[0x18], "x#3 = x#2 + 1", &["x#3"], &["x#2"]),
        );
        push_item(
            &mut medium,
            &mut block,
            item(
                &[0x20],
                "if (y#0 == 0) goto block_30 else goto block_40",
                &[],
                &["y#0"],
            ),
        );
        push_item(
            &mut medium,
            &mut block,
            item(&[0x30], "printf(\"x = %d\\n\", x#2)", &[], &["x#2"]),
        );
        medium.blocks.push(block);
        let mut high = medium.clone();
        high.level = Level::High;
        high.ssa = false;
        high.items.clear();
        high.blocks[0].items.clear();
        let mut block = high.blocks.remove(0);
        push_item(
            &mut high,
            &mut block,
            item(
                &[0x10, 0x14, 0x18],
                "for (x = 1; x <= a; x = x + 1)",
                &["x"],
                &["x", "a"],
            ),
        );
        push_item(
            &mut high,
            &mut block,
            item(&[0x20], "if (y != 0)", &[], &["y"]),
        );
        push_item(
            &mut high,
            &mut block,
            item(&[0x30], "printf(\"x = %d\\n\", x)", &[], &["x"]),
        );
        push_item(
            &mut high,
            &mut block,
            item(&[0x40], "while (z)", &[], &["z"]),
        );
        // A cast's type and a field are not names the header reads.
        push_item(
            &mut high,
            &mut block,
            item(&[0x14], "if ((long)x <= p->a)", &[], &["x", "p"]),
        );
        high.blocks.push(block);
        let ssa = to_ssa(&high, &Analysis::default(), Some(&medium));
        assert!(ssa.ssa);
        let texts: Vec<&str> = ssa.items.iter().map(|item| item.text.as_str()).collect();
        assert_eq!(texts[0], "for (x#1 = 1; x#2 <= a#0; x#3 = x#2 + 1)");
        assert_eq!(ssa.items[0].defines, vec!["x#1", "x#3"]);
        assert_eq!(ssa.items[0].uses, vec!["x#2", "a#0"]);
        // A condition the structurer turned round still finds its branch.
        assert_eq!(texts[1], "if (y#0 != 0)");
        assert_eq!(ssa.items[1].uses, vec!["y#0"]);
        // The literal is not a variable.
        assert_eq!(texts[2], "printf(\"x = %d\\n\", x#2)");
        // A header with no medium statement at its addresses keeps its names.
        assert_eq!(texts[3], "while (z)");
        assert_eq!(texts[4], "if ((long)x#2 <= p#0->a)");
        // Without the medium level there is no SSA form of the high.
        assert!(!to_ssa(&high, &Analysis::default(), None).ssa);
    }
}
