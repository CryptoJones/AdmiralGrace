//! The lifter: from the decoded x86-64 instructions of a function to a C
//! function.
//!
//! This is the third slice of the decompiler. It reads a function's whole
//! control-flow graph — straight-line code, branches and loops — and
//! anything it does not understand is refused with a reason ([`NotLifted`])
//! rather than guessed.
//!
//! # The graph
//!
//! The control-flow walk ends a block at every call, so a function that
//! calls is several blocks even when nothing in it branches. Blocks joined
//! only by fall-through — the block's last instruction is not a branch, its
//! one successor starts where it ends, and nothing else reaches that
//! successor — are lifted as one *node*. A node ends in `ret`, in a `jmp`,
//! in a `jcc`, or by falling into a node that other blocks also reach. The
//! graph of nodes is analyzed and structured by [`crate::structure`]:
//! dominators, natural loops from the back edges, `if`/`else`, `while`,
//! `do`/`while`, `for`, `break`, `continue`, early `return`, and `goto`
//! where nothing fits; a graph with a loop that has two entries is refused
//! as irreducible.
//!
//! # How it works
//!
//! Each node is walked once, instruction by instruction, with a symbolic
//! machine state:
//!
//! * **Registers are temporaries, not variables.** Each general register maps
//!   to the expression it currently holds, with the width of the last write.
//!   A 32-bit write zero-extends into the full register, so reading `rax`
//!   after writing `eax` is a zero-extension cast; reading `eax` after
//!   writing `rax` is a truncation. An 8- or 16-bit write leaves the upper
//!   bits alone, and a wider read after one is not tracked.
//! * **The stack pointer is tracked symbolically** as the entry stack pointer
//!   plus an offset, through `push`, `pop`, `sub rsp, N`, `mov rbp, rsp` and
//!   `leave`. A memory operand whose base is `rsp` or `rbp` with a known offset
//!   is a **stack slot**, keyed by its offset from the entry stack pointer and
//!   named `local_<hex>` (below the return address) or `stack_<hex>` (at or
//!   above it). Slots hold expressions too, so a value stored and loaded back
//!   is propagated: the copies through `[rbp-4]` and `[rbp-8]` in a `-O0`
//!   prologue vanish, and `return a + b;` comes out as the source wrote it.
//!   A slot becomes a real variable — declared, with its stores emitted —
//!   when its address is taken (`lea`), when it is read before it is
//!   written, or when it differs between two paths that join. A partial
//!   overwrite of a slot makes its value unknown.
//! * **The state is split at a branch and merged at a join.** Each successor
//!   starts from a copy of the state its predecessor ended in. Where paths
//!   join, a register or slot that holds the same expression on every path
//!   stays that expression; a slot that differs becomes a variable, assigned
//!   on each path by the stores already there; a register that differs
//!   becomes a declared variable named after the register (`eax`), assigned
//!   at the end of each path; a register one path never wrote, or whose value
//!   a call clobbered, becomes unknown, and is refused only if it is read.
//!   A stack pointer that differs between paths is refused. A loop header is
//!   lifted with the state of the paths into it, and the loop is lifted
//!   again with every register and slot the loop changes made a variable,
//!   until nothing more changes.
//! * **Conditions come from the flag producer.** `cmp`, `test` and the
//!   arithmetic instructions record what they compared or computed; a `jcc`
//!   turns that into a relation, with the signedness of the condition code —
//!   `cmp a, b; jl` is `a < b`, `jb` is `(unsigned int)a < (unsigned int)b`,
//!   `test x, x; je` is `x == 0`. A branch whose flags no tracked instruction
//!   set, or whose condition code does not fit the producer (`js` after
//!   `cmp`), is refused by name.
//! * **Parameters** are the argument registers of the calling convention
//!   (System V: `rdi, rsi, rdx, rcx, r8, r9`; Microsoft x64 for a `windows`
//!   language: `rcx, rdx, r8, r9`) that are read before they are written,
//!   named by position: `a`, `b`, `c`… The width of the first read fixes the
//!   type.
//! * **Calls** pass the argument registers written before the call, in
//!   convention order up to the first one not written; the result is `rax`,
//!   and the caller-saved registers are forgotten, and so is every value read
//!   from memory the callee could write. A call is a statement of its own;
//!   its result is a temporary (`v1`) that is inlined into the next
//!   statement when that is its only use.
//! * **Pointers** the code takes through `lea` off the instruction pointer
//!   are asked of the image ([`Symbols::pointee`]): one that lands on a
//!   string is that string's literal, one that lands on a named piece of
//!   data is `&name`, one that lands on a function is its name, and one the
//!   image does not know stays the address it is. A load or store through a
//!   pointer is a typed dereference, `*(int *)a`; one at an address the
//!   image names as data is that name, and one at an address it does not
//!   name is `*(int *)0x…`.
//! * **`ret`** returns `rax` with the width of its last write, or nothing if
//!   `rax` was never written; every `ret` of the function must agree.
//!
//! # The judgment calls
//!
//! Where the lifter could reasonably go either way — which argument
//! registers are parameters, how a merged register and a stack slot are
//! named, whether a load from named data is the name or a cast, the order
//! of the operands of `b + a`, whether an unsigned comparison is cast,
//! whether a `cmp` no branch reads is dropped, the calling convention — the
//! choice is an option of [`crate::options`], passed to [`lift_function`]
//! and documented by symptom in `docs/options.md`.
//!
//! # The type rule
//!
//! Types come from widths alone: 8 bits is `char`, 16 `short`, 32 `int` and
//! 64 `long`; the unsigned forms appear only in zero-extension casts and
//! unsigned comparisons. Nothing in a `mov` or an `add` says whether a value
//! is signed, so the signed name is the default. An argument register that
//! is passed on but never read has no width here, and is declared `long`.
//!
//! # What is refused
//!
//! 32-bit or 16-bit code; irreducible control flow; a node that ends in an
//! indirect jump or a trap; any mnemonic outside `mov`, `movsx`, `movsxd`,
//! `movzx`, `cdqe`, `add`, `sub`, `and`, `or`, `xor`, `inc`, `dec`, `imul`,
//! `lea`, `push`, `pop`, `leave`, `call`, `ret`, `cmp`, `test`, `jmp`, the
//! conditional jumps, `nop` and `endbr64`; an indirect call; a branch whose
//! flags are not tracked; a stack the lifter loses track of or that differs
//! between paths; `ret`s that disagree; and a value that reaches a
//! statement without being known — a register read before it is written
//! that is not an argument register, one clobbered by a call, or one that
//! two paths left different and the lifter could not name.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use iced_x86::Mnemonic;

use crate::arch::Bitness;
use crate::ast::{AstNode, BinaryOp};
use crate::cfg::ProcedureCfg;
use crate::cfgwalk::resolve_branches;
use crate::cpu_context::{DecodedInsn, Flow, Operand, RC_GPR, RC_IP, RC_NONE};
use crate::options::{
    DeadCompares, MergedNames, OperandOrder, Options, Parameters, PointerLoads, SlotNames,
    UnsignedCompare,
};
use crate::pipeline::Disasm;
use crate::register::RegisterId;
use crate::structure::{self, Analysis, Node, Terminator};

/// What the lifter asks the image: the name of a function it calls, and what
/// a pointer it takes lands on.
///
/// A plain function from an address to a function name is a `Symbols` that
/// knows no data, which is what the tests of the lifter use.
pub trait Symbols {
    /// The name of the function at `address`, when it has one.
    fn function_name(&self, address: u64) -> Option<String>;

    /// What the pointer to `address` lands on, when the image knows.
    fn pointee(&self, _address: u64) -> Option<Pointee> {
        None
    }
}

impl<F: Fn(u64) -> Option<String>> Symbols for F {
    fn function_name(&self, address: u64) -> Option<String> {
        self(address)
    }
}

/// What a pointer lands on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pointee {
    /// A string, from the pointer to its NUL: the text itself, unescaped.
    String(String),
    /// A named piece of data, which the pointer points at the start of.
    Data(String),
    /// A function, by its name.
    Function(String),
}

/// Why a function was not lifted.
///
/// The reason is a short phrase that completes "not lifted yet: …": the
/// mnemonic the lifter stopped at, the shape of the graph, or what it lost
/// track of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotLifted {
    /// What was not lifted.
    pub reason: String,
}

impl NotLifted {
    pub(crate) fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for NotLifted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not lifted yet: {}", self.reason)
    }
}

impl std::error::Error for NotLifted {}

/// The integer calling convention a program uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abi {
    /// System V AMD64: arguments in `rdi, rsi, rdx, rcx, r8, r9`.
    SystemV,
    /// Microsoft x64: arguments in `rcx, rdx, r8, r9`.
    Win64,
}

impl Abi {
    /// The convention a language id implies.
    ///
    /// The compiler field of the id names it: `x86:LE:64:default:windows` is
    /// Microsoft x64, and everything else is System V.
    pub fn of_language(language: &str) -> Abi {
        match language.split(':').nth(4) {
            Some("windows") => Abi::Win64,
            _ => Abi::SystemV,
        }
    }

    /// The argument registers, as GPR indices, in order.
    fn argument_registers(self) -> &'static [u32] {
        match self {
            Abi::SystemV => &[RDI, RSI, RDX, RCX, R8, R9],
            Abi::Win64 => &[RCX, RDX, R8, R9],
        }
    }

    /// Whether a call leaves the register alone.
    fn is_callee_saved(self, index: u32) -> bool {
        match self {
            Abi::SystemV => matches!(index, RBX | RSP | RBP | 12..=15),
            Abi::Win64 => matches!(index, RBX | RSP | RBP | RSI | RDI | 12..=15),
        }
    }
}

impl fmt::Display for Abi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Abi::SystemV => "System V",
            Abi::Win64 => "Microsoft x64",
        })
    }
}

/// A parameter or a local of a lifted function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    /// The C type.
    pub ty: String,
    /// The name.
    pub name: String,
}

/// One statement of a lifted function, with the instructions it came from.
///
/// A plain statement is its node; a control statement is its condition and
/// the statements it holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    /// The statement, or the condition of a control statement. A `while (1)`
    /// has [`AstNode::ConditionTrue`].
    pub node: AstNode,
    /// The addresses of the instructions that went into it, in order: for a
    /// control statement, the ones its condition and its jumps came from.
    pub addresses: Vec<u64>,
    /// What kind of statement it is.
    pub kind: StatementKind,
}

/// The kinds of statement.
#[derive(Debug, Clone, PartialEq)]
pub enum StatementKind {
    /// An expression, an assignment, a `return`, a `goto`, a label, a
    /// `break` or a `continue`.
    Plain,
    /// `if (cond) { then_part } else { else_part }`; the else may be empty.
    If {
        then_part: Vec<Statement>,
        else_part: Vec<Statement>,
    },
    /// `while (cond) { body }`.
    While { body: Vec<Statement> },
    /// `do { body } while (cond);`.
    DoWhile { body: Vec<Statement> },
    /// `for (init; cond; step) { body }`.
    For {
        init: Box<Statement>,
        step: Box<Statement>,
        body: Vec<Statement>,
    },
}

impl Statement {
    /// A plain statement.
    pub fn plain(node: AstNode, addresses: Vec<u64>) -> Self {
        Self {
            node,
            addresses,
            kind: StatementKind::Plain,
        }
    }

    /// The statement lists the statement holds.
    pub fn children(&self) -> Vec<&Vec<Statement>> {
        match &self.kind {
            StatementKind::Plain => Vec::new(),
            StatementKind::If {
                then_part,
                else_part,
            } => vec![then_part, else_part],
            StatementKind::While { body } | StatementKind::DoWhile { body } => vec![body],
            StatementKind::For { body, .. } => vec![body],
        }
    }

    /// The statement lists the statement holds, mutably.
    pub fn children_mut(&mut self) -> Vec<&mut Vec<Statement>> {
        match &mut self.kind {
            StatementKind::Plain => Vec::new(),
            StatementKind::If {
                then_part,
                else_part,
            } => vec![then_part, else_part],
            StatementKind::While { body } | StatementKind::DoWhile { body } => vec![body],
            StatementKind::For { body, .. } => vec![body],
        }
    }

    /// Every address the statement and the statements it holds came from.
    pub fn claimed(&self, out: &mut BTreeSet<u64>) {
        out.extend(self.addresses.iter().copied());
        if let StatementKind::For { init, step, .. } = &self.kind {
            init.claimed(out);
            step.claimed(out);
        }
        for child in self.children() {
            for statement in child {
                statement.claimed(out);
            }
        }
    }

    /// Whether the statement, or one it holds, reads or assigns `name`.
    fn mentions(&self, name: &str) -> bool {
        self.node.reads_var(name)
            || self.node.assigned_var() == Some(name)
            || match &self.kind {
                StatementKind::For { init, step, .. } => init.mentions(name) || step.mentions(name),
                _ => false,
            }
            || self
                .children()
                .iter()
                .any(|child| child.iter().any(|statement| statement.mentions(name)))
    }
}

/// A function lifted to C.
#[derive(Debug, Clone)]
pub struct LiftedFunction {
    /// The function's name.
    pub name: String,
    /// The function's entry address.
    pub address: u64,
    /// The C return type; `void` when `rax` is never written.
    pub return_type: String,
    /// The parameters, in order.
    pub params: Vec<Variable>,
    /// The locals, in the order they are declared.
    pub locals: Vec<Variable>,
    /// The statements of the body, in order.
    pub body: Vec<Statement>,
    /// The instructions no statement came from: the frame setup and
    /// teardown, and the no-ops. The signature line stands for them.
    pub frame: Vec<u64>,
}

// The GPR indices iced numbers the registers by.
const RAX: u32 = 0;
const RCX: u32 = 1;
const RDX: u32 = 2;
const RBX: u32 = 3;
const RSP: u32 = 4;
const RBP: u32 = 5;
const RSI: u32 = 6;
const RDI: u32 = 7;
const R8: u32 = 8;
const R9: u32 = 9;

/// How many times the loops of a function are lifted again before the
/// lifter gives up on them settling.
const PASSES: usize = 8;

/// Lift the function at `entry` through its control-flow graph.
///
/// `symbols` gives the name of the function at an address, for the calls the
/// body makes — a call to an address with no name is `sub_<hex>` — and what
/// a pointer the body takes lands on. `options` decides the judgment calls
/// ([`crate::options`]): the lifter's own, and the structurer's.
#[allow(clippy::too_many_arguments)]
pub fn lift_function(
    disasm: &Disasm,
    cfg: &ProcedureCfg,
    entry: u64,
    name: &str,
    bitness: Bitness,
    abi: Abi,
    symbols: &dyn Symbols,
    options: &Options,
) -> Result<LiftedFunction, NotLifted> {
    if bitness != Bitness::Bits64 {
        return Err(NotLifted::new(format!("{bitness} code")));
    }
    let chains = chains(disasm, cfg, entry)?;
    let successors: Vec<Vec<usize>> = chains.iter().map(|chain| chain.end.successors()).collect();
    let analysis = structure::analyze(&successors, 0, |node| chains[node].address)?;
    let mut lifter = Lifter::new(abi, symbols, *options);
    let lifted = lifter.lift_chains(&chains, &analysis)?;
    let nodes = lifter.resolve_all(&chains, lifted)?;
    let body = structure::structure(&nodes, &analysis, 0, options);
    lifter.finish(name, entry, &chains, body)
}

/// Lift a run of instructions as a function entered at `entry`: the graph
/// is built from the instructions alone.
pub fn lift_block(
    instructions: &[DecodedInsn],
    entry: u64,
    name: &str,
    abi: Abi,
    symbols: &dyn Symbols,
    options: &Options,
) -> Result<LiftedFunction, NotLifted> {
    let disasm = Disasm {
        file_offset_of_segment: 0,
        instructions: instructions.to_vec(),
    };
    let cfg = resolve_branches(&disasm, entry);
    lift_function(
        &disasm,
        &cfg,
        entry,
        name,
        Bitness::Bits64,
        abi,
        symbols,
        options,
    )
}

/// How a chain of blocks ends.
#[derive(Debug, Clone)]
enum End {
    /// In `ret`.
    Return,
    /// In a `jmp` to the chain.
    Jump(usize),
    /// In a `jcc`: to `taken` when it holds, else into `next`.
    Branch { taken: usize, next: usize },
    /// By falling into the chain, which other blocks also reach.
    Fall(usize),
}

impl End {
    fn successors(&self) -> Vec<usize> {
        match self {
            End::Return => Vec::new(),
            End::Jump(target) | End::Fall(target) => vec![*target],
            End::Branch { taken, next } => vec![*taken, *next],
        }
    }
}

/// Blocks joined only by fall-through, lifted as one node of the graph.
#[derive(Debug, Clone)]
struct Chain {
    /// The address of the first instruction.
    address: u64,
    /// The instructions, in order.
    instructions: Vec<DecodedInsn>,
    /// How the chain ends.
    end: End,
}

/// The chains of the function at `entry`, the entry's first.
///
/// A block is followed into its successor when its last instruction is not
/// a branch or a return, its one successor starts where the block ends, and
/// no other block has that successor; the chain ends at the first block
/// that does not. A chain whose last block has no successor must end in
/// `ret`; one that ends in an indirect jump or a trap is refused as `the
/// block ends in <mnemonic>`.
fn chains(disasm: &Disasm, cfg: &ProcedureCfg, entry: u64) -> Result<Vec<Chain>, NotLifted> {
    let block_at = |address: u64| cfg.blocks.iter().find(|block| block.from == address);
    let mut predecessors: BTreeMap<u64, usize> = BTreeMap::new();
    for block in &cfg.blocks {
        for &successor in &block.successor_addresses {
            *predecessors.entry(successor).or_default() += 1;
        }
    }

    let mut starts = vec![entry];
    let mut seen = BTreeSet::from([entry]);
    let mut raw: Vec<(u64, Vec<DecodedInsn>, Vec<u64>)> = Vec::new();
    let mut i = 0;
    while i < starts.len() {
        let start = starts[i];
        i += 1;
        let Some(mut block) = block_at(start) else {
            return Err(NotLifted::new(format!("no code at {start:#x}")));
        };
        let mut instructions: Vec<DecodedInsn> = Vec::new();
        loop {
            instructions.extend(
                disasm
                    .instructions
                    .iter()
                    .filter(|ins| block.contains(ins.address))
                    .cloned(),
            );
            let last = instructions.last();
            let continues = last.is_some_and(|ins| !branches(ins) && ins.flow != Flow::Return)
                && block.successor_addresses.as_slice() == [block.to]
                && predecessors.get(&block.to) == Some(&1);
            if !continues {
                break;
            }
            // Each block starts where the one before ends, so the chain
            // climbs through memory and cannot come round.
            block = block_at(block.to)
                .ok_or_else(|| NotLifted::new(format!("no code at {:#x}", block.to)))?;
        }
        for &successor in &block.successor_addresses {
            if seen.insert(successor) {
                starts.push(successor);
            }
        }
        raw.push((start, instructions, block.successor_addresses.clone()));
    }

    let index: BTreeMap<u64, usize> = raw
        .iter()
        .enumerate()
        .map(|(i, (address, _, _))| (*address, i))
        .collect();
    let node_at = |address: u64| {
        index
            .get(&address)
            .copied()
            .ok_or_else(|| NotLifted::new(format!("jumps to {address:#x}")))
    };
    raw.into_iter()
        .map(|(address, instructions, successors)| {
            let Some(last) = instructions.last() else {
                return Err(NotLifted::new(format!("no code at {address:#x}")));
            };
            let after = last.address + last.length as u64;
            let end = match last.flow {
                Flow::Return => End::Return,
                Flow::UnconditionalBranch(target) => End::Jump(node_at(target)?),
                Flow::ConditionalBranch(target) if target == after => End::Jump(node_at(after)?),
                Flow::ConditionalBranch(target) => End::Branch {
                    taken: node_at(target)?,
                    next: node_at(after)?,
                },
                _ => match successors.as_slice() {
                    [next] if *next == after => End::Fall(node_at(after)?),
                    _ => {
                        return Err(NotLifted::new(format!(
                            "the block ends in {}",
                            mnemonic_name(last)
                        )))
                    }
                },
            };
            Ok(Chain {
                address,
                instructions,
                end,
            })
        })
        .collect()
}

/// Whether the instruction is a branch of any kind: it may go somewhere
/// other than the next instruction, and not by calling or returning.
fn branches(ins: &DecodedInsn) -> bool {
    matches!(
        ins.flow,
        Flow::UnconditionalBranch(_)
            | Flow::ConditionalBranch(_)
            | Flow::Xbegin(_)
            | Flow::IndirectBranch
    )
}

/// What a register or a stack slot holds.
#[derive(Debug, Clone)]
enum Sym {
    /// A C expression.
    Node(AstNode),
    /// The entry stack pointer plus an offset.
    Stack(i64),
    /// The value a register had at entry; not a parameter.
    Entry(u32),
    /// The result of the call that made temporary `n`.
    Temp(usize),
    /// Not tracked, and why.
    Unknown(String),
}

/// A value, its width, and the instructions that produced it.
#[derive(Debug, Clone)]
struct Value {
    sym: Sym,
    bits: u32,
    from: Vec<u64>,
}

impl Value {
    fn new(sym: Sym, bits: u32, from: Vec<u64>) -> Self {
        Self { sym, bits, from }
    }

    fn node(node: AstNode, bits: u32, from: Vec<u64>) -> Self {
        Self::new(Sym::Node(node), bits, from)
    }

    fn unknown(reason: impl Into<String>, bits: u32) -> Self {
        Self::new(Sym::Unknown(reason.into()), bits, Vec::new())
    }

    /// The value with one more producing instruction.
    fn also_from(mut self, address: u64) -> Self {
        self.from.push(address);
        self
    }

    /// Whether the value can be written as an expression: a node or a call
    /// result. The stack pointer, an entry value and an unknown cannot.
    fn is_expression(&self) -> bool {
        matches!(self.sym, Sym::Node(_) | Sym::Temp(_))
    }

    /// Whether the value's expression reads the variable `name`.
    fn reads_var(&self, name: &str) -> bool {
        matches!(&self.sym, Sym::Node(node) if node.reads_var(name))
    }
}

/// Whether two values are the same: the same expression at the same width,
/// the producing instructions aside. Two unknowns are the same unknown.
fn same(a: &Value, b: &Value) -> bool {
    a.bits == b.bits
        && match (&a.sym, &b.sym) {
            (Sym::Node(x), Sym::Node(y)) => x == y,
            (Sym::Stack(x), Sym::Stack(y)) => x == y,
            (Sym::Entry(x), Sym::Entry(y)) => x == y,
            (Sym::Temp(x), Sym::Temp(y)) => x == y,
            (Sym::Unknown(_), Sym::Unknown(_)) => true,
            _ => false,
        }
}

/// A stack slot: what it holds and how wide it is.
#[derive(Debug, Clone)]
struct Slot {
    bits: u32,
    value: Value,
}

/// What set the flags last.
#[derive(Debug, Clone)]
enum Producer {
    /// `cmp lhs, rhs`.
    Cmp(Value, Value),
    /// `test lhs, rhs`.
    Test(Value, Value),
    /// An arithmetic instruction, by its result.
    Result(Value),
}

/// The flags: what set them, at what width, and where.
#[derive(Debug, Clone)]
struct Flags {
    producer: Producer,
    bits: u32,
    /// The producing instruction.
    at: u64,
    /// Its mnemonic, for the refusal.
    mnemonic: String,
}

/// The symbolic machine state at one point of the function.
#[derive(Debug, Clone)]
struct State {
    /// What each general register holds, by GPR index.
    regs: BTreeMap<u32, Value>,
    /// The stack slots, by offset from the entry stack pointer.
    stack: BTreeMap<i64, Slot>,
    /// What set the flags, if anything tracked did.
    flags: Option<Flags>,
}

impl State {
    /// The state at entry: the stack pointer is the entry stack pointer.
    fn initial() -> Self {
        let mut regs = BTreeMap::new();
        regs.insert(RSP, Value::new(Sym::Stack(0), 64, Vec::new()));
        Self {
            regs,
            stack: BTreeMap::new(),
            flags: None,
        }
    }

    fn empty() -> Self {
        Self {
            regs: BTreeMap::new(),
            stack: BTreeMap::new(),
            flags: None,
        }
    }

    fn get(&self, key: Key) -> Option<&Value> {
        match key {
            Key::Reg(index) => self.regs.get(&index),
            Key::Slot(offset) => self.stack.get(&offset).map(|slot| &slot.value),
        }
    }

    /// Whether a slot other than one starting at `offset` with `bits`
    /// overlaps the `bits` bits at `offset`.
    fn overlaps(&self, offset: i64, bits: u32) -> bool {
        let end = offset + i64::from(bits / 8);
        self.stack.iter().any(|(&start, slot)| {
            let slot_end = start + i64::from(slot.bits / 8);
            start < end && offset < slot_end && !(start == offset && slot.bits == bits)
        })
    }

    /// The keys the state holds.
    fn keys(&self) -> impl Iterator<Item = Key> + '_ {
        self.regs
            .keys()
            .map(|&index| Key::Reg(index))
            .chain(self.stack.keys().map(|&offset| Key::Slot(offset)))
    }
}

/// A register or a stack slot, as a key of the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Reg(u32),
    Slot(i64),
}

/// What a key that differs between paths becomes.
#[derive(Debug, Clone, PartialEq)]
enum Forced {
    /// A declared variable of `bits` bits, assigned on each path.
    Var { bits: u32 },
    /// Unknown, refused if read.
    Unknown { reason: String, bits: u32 },
}

/// How a key merges across paths.
enum Resolution {
    /// The same on every path.
    Same(Value),
    /// Different, and a variable.
    Var { bits: u32 },
    /// Different, and not something a variable could hold.
    Unknown { reason: String, bits: u32 },
}

/// A call result, named `v1`, `v2`… once it is used.
#[derive(Debug, Clone)]
struct Temp {
    name: String,
    /// The width the result is read at; `None` until it is read.
    bits: Option<u32>,
}

/// A statement before the temporaries are resolved.
#[derive(Debug, Clone)]
enum Stmt {
    /// A call whose result is `temp`.
    Call {
        temp: usize,
        node: AstNode,
        addresses: Vec<u64>,
    },
    /// A store to a stack slot; emitted only if the slot is a variable.
    Store {
        offset: i64,
        bits: u32,
        value: Value,
        addresses: Vec<u64>,
    },
    /// `lhs = value`: a store through a pointer, or a variable's assignment.
    Assign {
        lhs: AstNode,
        value: Value,
        addresses: Vec<u64>,
    },
    /// The return.
    Return {
        value: Option<Value>,
        addresses: Vec<u64>,
    },
    /// A `cmp` or `test` kept as a statement under `dead-compares keep`:
    /// `__cmp(lhs, rhs);`. Removed again when a branch reads its flags.
    Compare {
        name: &'static str,
        lhs: Value,
        rhs: Value,
        addresses: Vec<u64>,
    },
}

/// The statements each path into a join appends, by the path's node.
type Assignments = Vec<(usize, Vec<Stmt>)>;

/// A register two paths left different, declared as a variable.
#[derive(Debug, Clone)]
struct Merged {
    name: String,
    bits: u32,
}

struct Lifter<'a> {
    abi: Abi,
    symbols: &'a dyn Symbols,
    /// The judgment calls, as the run set them.
    options: Options,
    /// The `cmp` or `test` statement kept under `dead-compares keep` whose
    /// flags no branch has read yet: the producing address and the
    /// statement's index in the chain.
    pending_compare: Option<(u64, usize)>,
    /// The state at the instruction being lifted.
    state: State,
    /// The slots whose address was taken.
    address_taken: BTreeSet<i64>,
    /// The slots that are variables, with their width.
    locals: BTreeMap<i64, u32>,
    /// The parameters read so far: position to width.
    params: BTreeMap<usize, u32>,
    temps: Vec<Temp>,
    /// The values saved into a temporary before the variable they were
    /// computed from changed.
    saved: Vec<Variable>,
    /// The registers that became variables at a join, by the join's address
    /// and the register.
    merged: BTreeMap<(u64, u32), Merged>,
    /// The names of the global data the body reads or writes.
    globals: BTreeSet<String>,
    /// The statements of the chain being lifted.
    statements: Vec<Stmt>,
    /// The width of the return value, once a `ret` is seen: `Some(None)`
    /// for a `ret` with `rax` never written.
    returns: Option<Option<u32>>,
    /// The temporaries declared, once the statements are resolved.
    declared: Vec<Variable>,
}

impl<'a> Lifter<'a> {
    fn new(abi: Abi, symbols: &'a dyn Symbols, options: Options) -> Self {
        Self {
            abi,
            symbols,
            options,
            pending_compare: None,
            state: State::initial(),
            address_taken: BTreeSet::new(),
            locals: BTreeMap::new(),
            params: BTreeMap::new(),
            temps: Vec::new(),
            saved: Vec::new(),
            merged: BTreeMap::new(),
            globals: BTreeSet::new(),
            statements: Vec::new(),
            returns: None,
            declared: Vec::new(),
        }
    }

    /// Forget what one pass over the function found, keeping what holds
    /// across passes: the slots whose address is taken, and the names of
    /// the registers that became variables.
    fn reset(&mut self) {
        self.state = State::initial();
        self.locals.clear();
        self.params.clear();
        self.temps.clear();
        self.saved.clear();
        self.globals.clear();
        self.statements.clear();
        self.returns = None;
    }

    // ---- the graph --------------------------------------------------------

    /// Lift every chain, in reverse post-order, merging the state at each
    /// join and lifting the loops again until they settle.
    fn lift_chains(
        &mut self,
        chains: &[Chain],
        analysis: &Analysis,
    ) -> Result<Vec<(Vec<Stmt>, Terminator)>, NotLifted> {
        let count = chains.len();
        let mut forced: Vec<BTreeMap<Key, Forced>> = vec![BTreeMap::new(); count];
        for _ in 0..PASSES {
            self.reset();
            for keys in &forced {
                for (key, what) in keys {
                    if let (Key::Slot(offset), Forced::Var { bits }) = (key, what) {
                        self.locals.insert(*offset, *bits);
                    }
                }
            }
            let mut ins: Vec<Option<State>> = vec![None; count];
            let mut outs: Vec<Option<State>> = vec![None; count];
            let mut lifted: Vec<Option<(Vec<Stmt>, Terminator)>> = vec![None; count];
            let mut appended: Vec<Vec<Stmt>> = vec![Vec::new(); count];

            for &node in &analysis.rpo {
                let at = chains[node].address;
                let state = if node == 0 {
                    State::initial()
                } else {
                    let inputs: Vec<(usize, State)> = analysis.preds[node]
                        .iter()
                        .filter(|&&pred| !analysis.is_back_edge(pred, node))
                        .map(|&pred| {
                            (
                                pred,
                                outs[pred]
                                    .clone()
                                    .expect("a forward predecessor is lifted first"),
                            )
                        })
                        .collect();
                    let (mut state, assignments) = self.merge(at, &inputs)?;
                    for (pred, statements) in assignments {
                        appended[pred].extend(statements);
                    }
                    self.force(&mut state, at, &forced[node], &inputs, &mut appended)?;
                    state
                };
                ins[node] = Some(state.clone());
                self.state = state;
                self.statements.clear();
                let terminator = self.lift_chain(&chains[node])?;
                // A latch assigns the registers its loop made variables,
                // and holds the variables from there on.
                for (&header, lp) in &analysis.loops {
                    if !lp.latches.contains(&node) {
                        continue;
                    }
                    let at = chains[header].address;
                    for (key, what) in &forced[header] {
                        let (Key::Reg(index), Forced::Var { bits }) = (key, what) else {
                            continue;
                        };
                        let name = self.merged_variable(at, *index, *bits);
                        let state = self.state.clone();
                        if let Some(statement) =
                            self.assignment(&name, *index, *bits, &state, at)?
                        {
                            if let Stmt::Assign { value, .. } = &statement {
                                self.variable_changed(&name, value, chains[node].address);
                            }
                            self.state
                                .regs
                                .insert(*index, Value::node(AstNode::var(name), *bits, Vec::new()));
                            appended[node].push(statement);
                        }
                    }
                }
                outs[node] = Some(self.state.clone());
                lifted[node] = Some((std::mem::take(&mut self.statements), terminator));
            }

            // Compare each loop's latches with its header: what differs is
            // made a variable, and the function is lifted again.
            let mut changed = false;
            for (&header, lp) in &analysis.loops {
                let head = ins[header].as_ref().expect("every node is lifted");
                for &latch in &lp.latches {
                    let out = outs[latch].as_ref().expect("every node is lifted");
                    for (key, what) in self.compare(chains[header].address, head, out)? {
                        if forced[header].get(&key) != Some(&what) {
                            forced[header].insert(key, what);
                            changed = true;
                        }
                    }
                }
            }
            if changed {
                continue;
            }
            return Ok(lifted
                .into_iter()
                .zip(appended)
                .map(|(lifted, appended)| {
                    let (mut statements, mut terminator) = lifted.expect("every node is lifted");
                    // A condition computed before the path assigned a
                    // variable reads the variable: `(edi - 1) != 0` after
                    // `edi = edi - 1` is `edi != 0`.
                    if let Terminator::Branch { cond, .. } = &mut terminator {
                        for statement in &appended {
                            if let Stmt::Assign {
                                lhs,
                                value:
                                    Value {
                                        sym: Sym::Node(expression),
                                        ..
                                    },
                                ..
                            } = statement
                            {
                                *cond = cond.clone().replace(expression, lhs);
                            }
                        }
                    }
                    statements.extend(appended);
                    (statements, terminator)
                })
                .collect());
        }
        Err(NotLifted::new("the loops do not settle"))
    }

    /// Lift one chain from the current state, and say how it leaves.
    fn lift_chain(&mut self, chain: &Chain) -> Result<Terminator, NotLifted> {
        self.pending_compare = None;
        let (last, body) = chain
            .instructions
            .split_last()
            .expect("a chain has an instruction");
        for ins in body {
            self.step(ins)?;
        }
        match chain.end {
            End::Return => {
                self.step(last)?;
                Ok(Terminator::Return)
            }
            End::Fall(target) => {
                self.step(last)?;
                Ok(Terminator::Goto {
                    target,
                    addresses: Vec::new(),
                })
            }
            End::Jump(target) => Ok(Terminator::Goto {
                target,
                addresses: vec![last.address],
            }),
            End::Branch { taken, next } => {
                let (cond, addresses) = self.condition(last)?;
                Ok(Terminator::Branch {
                    cond,
                    taken,
                    next,
                    addresses,
                })
            }
        }
    }

    /// Merge the states of the paths into the node at `at`.
    ///
    /// Returns the merged state and, per path, the assignments that path
    /// makes to the registers that became variables.
    fn merge(
        &mut self,
        at: u64,
        inputs: &[(usize, State)],
    ) -> Result<(State, Assignments), NotLifted> {
        if let [(_, only)] = inputs {
            return Ok((only.clone(), Vec::new()));
        }
        let states: Vec<&State> = inputs.iter().map(|(_, state)| state).collect();
        let keys: BTreeSet<Key> = states.iter().flat_map(|state| state.keys()).collect();
        let mut out = State::empty();
        let mut assignments: Assignments =
            inputs.iter().map(|(pred, _)| (*pred, Vec::new())).collect();
        let mut named: Vec<String> = Vec::new();

        for key in keys {
            match self.resolve_key(key, &states, at)? {
                Resolution::Same(value) => match key {
                    Key::Reg(index) => {
                        out.regs.insert(index, value);
                    }
                    Key::Slot(offset) => {
                        let bits = value.bits;
                        out.stack.insert(offset, Slot { bits, value });
                    }
                },
                Resolution::Var { bits } => match key {
                    Key::Slot(offset) => {
                        self.locals.entry(offset).or_insert(bits);
                        out.stack.insert(
                            offset,
                            Slot {
                                bits,
                                value: Value::node(
                                    AstNode::var(local_name(self.options.stack_slot_names, offset)),
                                    bits,
                                    Vec::new(),
                                ),
                            },
                        );
                    }
                    Key::Reg(index) => {
                        let name = self.merged_variable(at, index, bits);
                        out.regs.insert(
                            index,
                            Value::node(AstNode::var(name.clone()), bits, Vec::new()),
                        );
                        for (i, (_, state)) in inputs.iter().enumerate() {
                            if let Some(statement) =
                                self.assignment(&name, index, bits, state, at)?
                            {
                                assignments[i].1.push(statement);
                            }
                        }
                        named.push(name);
                    }
                },
                Resolution::Unknown { reason, bits } => match key {
                    Key::Reg(index) => {
                        out.regs.insert(index, Value::unknown(reason, bits));
                    }
                    Key::Slot(offset) => {
                        out.stack.insert(
                            offset,
                            Slot {
                                bits,
                                value: Value::unknown(reason, bits),
                            },
                        );
                    }
                },
            }
        }

        // A value computed from a register variable before the paths
        // assigned it is stale now.
        for name in &named {
            for (index, value) in out.regs.iter_mut() {
                if value.reads_var(name)
                    && !matches!(&value.sym, Sym::Node(AstNode::Var { name: n }) if n == name)
                {
                    *value = Value::unknown(
                        format!(
                            "{} was computed from {name} before the join at {at:#x}",
                            gpr_name(*index, value.bits)
                        ),
                        value.bits,
                    );
                }
            }
            for (offset, slot) in out.stack.iter_mut() {
                if slot.value.reads_var(name) {
                    slot.value = Value::unknown(
                        format!(
                            "{} was computed from {name} before the join at {at:#x}",
                            local_name(self.options.stack_slot_names, *offset)
                        ),
                        slot.bits,
                    );
                }
            }
        }

        // The flags survive a join only when every path set them the same
        // way.
        let first = states[0].flags.as_ref();
        if let Some(flags) = first {
            if states.iter().all(|state| {
                state
                    .flags
                    .as_ref()
                    .is_some_and(|other| other.at == flags.at)
            }) {
                out.flags = Some(flags.clone());
            }
        }
        Ok((out, assignments))
    }

    /// How `key` merges across `states`, at the join `at`.
    fn resolve_key(
        &mut self,
        key: Key,
        states: &[&State],
        at: u64,
    ) -> Result<Resolution, NotLifted> {
        let values: Vec<Option<&Value>> = states.iter().map(|state| state.get(key)).collect();
        let present: Vec<&Value> = values.iter().flatten().copied().collect();
        let all_present = present.len() == values.len();
        if all_present && present.windows(2).all(|pair| same(pair[0], pair[1])) {
            return Ok(Resolution::Same(present[0].clone()));
        }
        if key == Key::Reg(RSP) {
            return Err(NotLifted::new(format!(
                "the stack pointer differs at {at:#x}"
            )));
        }
        let bits_of = |value: &Value| match value.sym {
            Sym::Temp(temp) => self.temps[temp].bits.unwrap_or(value.bits),
            _ => value.bits,
        };
        let bits = present
            .iter()
            .map(|value| bits_of(value))
            .max()
            .unwrap_or(64);
        let agree = present.iter().all(|value| bits_of(value) == bits);
        let expressions = present.iter().all(|value| value.is_expression());
        match key {
            Key::Reg(index) => {
                // An argument register a path never wrote still holds its
                // parameter there.
                let known = all_present || self.parameter_of(index, bits).is_some();
                if known && expressions && agree {
                    Ok(Resolution::Var { bits })
                } else {
                    Ok(Resolution::Unknown {
                        reason: format!("{} differs at {at:#x}", gpr_name(index, 64)),
                        bits: 64,
                    })
                }
            }
            Key::Slot(offset) => {
                let in_parts = states
                    .iter()
                    .zip(&values)
                    .any(|(state, value)| value.is_none() && state.overlaps(offset, bits));
                if expressions && agree && !in_parts {
                    Ok(Resolution::Var { bits })
                } else {
                    Ok(Resolution::Unknown {
                        reason: format!(
                            "{} differs at {at:#x}",
                            local_name(self.options.stack_slot_names, offset)
                        ),
                        bits,
                    })
                }
            }
        }
    }

    /// Make the keys of `forced` what the loop's latches made them, in the
    /// state of its header at `at`; the paths into the header assign the
    /// registers that became variables.
    fn force(
        &mut self,
        state: &mut State,
        at: u64,
        forced: &BTreeMap<Key, Forced>,
        inputs: &[(usize, State)],
        appended: &mut [Vec<Stmt>],
    ) -> Result<(), NotLifted> {
        for (key, what) in forced {
            match (key, what) {
                (Key::Slot(offset), Forced::Var { bits }) => {
                    state.stack.insert(
                        *offset,
                        Slot {
                            bits: *bits,
                            value: Value::node(
                                AstNode::var(local_name(self.options.stack_slot_names, *offset)),
                                *bits,
                                Vec::new(),
                            ),
                        },
                    );
                }
                (Key::Slot(offset), Forced::Unknown { reason, bits }) => {
                    state.stack.insert(
                        *offset,
                        Slot {
                            bits: *bits,
                            value: Value::unknown(reason.clone(), *bits),
                        },
                    );
                }
                (Key::Reg(index), Forced::Var { bits }) => {
                    let name = self.merged_variable(at, *index, *bits);
                    state.regs.insert(
                        *index,
                        Value::node(AstNode::var(name.clone()), *bits, Vec::new()),
                    );
                    for (pred, input) in inputs {
                        if let Some(statement) = self.assignment(&name, *index, *bits, input, at)? {
                            appended[*pred].push(statement);
                        }
                    }
                }
                (Key::Reg(index), Forced::Unknown { reason, .. }) => {
                    state
                        .regs
                        .insert(*index, Value::unknown(reason.clone(), 64));
                }
            }
        }
        Ok(())
    }

    /// What the latch's state makes of the header's: the keys that differ,
    /// and what they become.
    fn compare(
        &mut self,
        at: u64,
        head: &State,
        latch: &State,
    ) -> Result<Vec<(Key, Forced)>, NotLifted> {
        let keys: BTreeSet<Key> = head.keys().chain(latch.keys()).collect();
        let mut forced = Vec::new();
        for key in keys {
            match self.resolve_key(key, &[head, latch], at)? {
                Resolution::Same(_) => {}
                Resolution::Var { bits } => forced.push((key, Forced::Var { bits })),
                Resolution::Unknown { reason, bits } => {
                    forced.push((key, Forced::Unknown { reason, bits }))
                }
            }
        }
        Ok(forced)
    }

    /// The parameter the argument register `index` holds at entry, read at
    /// `bits`; `None` for a register that is not an argument register.
    fn parameter_of(&mut self, index: u32, bits: u32) -> Option<Value> {
        let position = self
            .abi
            .argument_registers()
            .iter()
            .position(|&register| register == index)?;
        let width = *self.params.entry(position).or_insert(bits);
        Some(Value::node(
            AstNode::var(parameter_name(position)),
            width,
            Vec::new(),
        ))
    }

    /// The assignment `name = <the register's value in state>`, when the
    /// state does not already hold the variable.
    fn assignment(
        &mut self,
        name: &str,
        index: u32,
        bits: u32,
        state: &State,
        at: u64,
    ) -> Result<Option<Stmt>, NotLifted> {
        let held = match state.regs.get(&index) {
            Some(value) => Some(value.clone()),
            None => self.parameter_of(index, bits),
        };
        let Some(value) = held.as_ref() else {
            return Ok(None);
        };
        if matches!(&value.sym, Sym::Node(AstNode::Var { name: n }) if n == name) {
            return Ok(None);
        }
        if !value.is_expression() {
            return Ok(None);
        }
        let value = self.at_width(value.clone(), bits, index, at)?;
        let addresses = sorted(value.from.iter().copied());
        Ok(Some(Stmt::Assign {
            lhs: AstNode::var(name),
            value,
            addresses,
        }))
    }

    /// The variable the register `index` is at the join `at`, named after
    /// the register at its width, with a suffix if the name is taken.
    fn merged_variable(&mut self, at: u64, index: u32, bits: u32) -> String {
        if let Some(merged) = self.merged.get(&(at, index)) {
            return merged.name.clone();
        }
        let (base, mut name, mut n) = match self.options.merged_register_names {
            MergedNames::Register => {
                let base = gpr_name(index, bits);
                (base.clone(), base, 1)
            }
            MergedNames::Numbered => ("var".to_string(), "var_1".to_string(), 1),
        };
        while self.merged.values().any(|merged| merged.name == name) {
            n += 1;
            name = format!("{base}_{n}");
        }
        self.merged.insert(
            (at, index),
            Merged {
                name: name.clone(),
                bits,
            },
        );
        name
    }

    // ---- registers --------------------------------------------------------

    /// The GPR index of a register operand, refusing anything else.
    fn gpr(&self, reg: RegisterId) -> Result<u32, NotLifted> {
        if reg.class != RC_GPR {
            return Err(NotLifted::new("a register that is not a general one"));
        }
        if reg.bit_offset != 0 {
            return Err(NotLifted::new(format!(
                "the high byte register {}",
                high_byte_name(reg.index)
            )));
        }
        Ok(reg.index)
    }

    /// Read a register at its operand width.
    fn read(&mut self, reg: RegisterId, at: u64) -> Result<Value, NotLifted> {
        let index = self.gpr(reg)?;
        let bits = reg.bit_size;
        let held = match self.state.regs.get(&index) {
            Some(value) => value.clone(),
            None => self.entry_value(index, bits),
        };
        self.at_width(held, bits, index, at)
    }

    /// The value a register has at entry: a parameter if it is an argument
    /// register, otherwise whatever the caller left in it.
    fn entry_value(&mut self, index: u32, bits: u32) -> Value {
        let position = self
            .abi
            .argument_registers()
            .iter()
            .position(|&register| register == index);
        let value = match position {
            Some(position) => {
                self.params.insert(position, bits);
                Value::node(AstNode::var(parameter_name(position)), bits, Vec::new())
            }
            None => Value::new(Sym::Entry(index), 64, Vec::new()),
        };
        self.state.regs.insert(index, value.clone());
        value
    }

    /// A value read at `bits` when it was written at its own width.
    fn at_width(
        &mut self,
        value: Value,
        bits: u32,
        index: u32,
        at: u64,
    ) -> Result<Value, NotLifted> {
        if let Sym::Temp(temp) = value.sym {
            let temp = &mut self.temps[temp];
            let known = *temp.bits.get_or_insert(bits);
            let node = AstNode::var(temp.name.clone());
            let node = if known == bits {
                node
            } else {
                cast(node, known, bits)
            };
            return Ok(Value::node(node, bits, value.from));
        }
        if value.bits == bits {
            return Ok(value);
        }
        let Value {
            sym,
            bits: had,
            from,
        } = value;
        let node = match sym {
            Sym::Node(AstNode::Constant { value, .. }) => {
                AstNode::constant(value & mask(bits), bits / 8)
            }
            Sym::Node(node) if bits < had || had == 32 => cast(node, had, bits),
            Sym::Node(_) => {
                return Ok(Value::unknown(
                    format!(
                        "the upper bits of {} after a {had}-bit write",
                        gpr_name(index, bits)
                    ),
                    bits,
                ))
            }
            Sym::Unknown(reason) => return Ok(Value::unknown(reason, bits)),
            Sym::Stack(_) => {
                return Ok(Value::unknown(
                    format!("the stack pointer read as {bits} bits at {at:#x}"),
                    bits,
                ))
            }
            Sym::Entry(_) if bits > had => {
                return Err(NotLifted::new(format!(
                    "{} is read as {bits} bits after {}",
                    gpr_name(index, bits),
                    gpr_name(index, had)
                )))
            }
            Sym::Entry(index) => return Ok(Value::new(Sym::Entry(index), bits, from)),
            Sym::Temp(_) => unreachable!("handled above"),
        };
        Ok(Value::node(node, bits, from))
    }

    /// Write a register at its operand width.
    fn write(&mut self, reg: RegisterId, value: Value) -> Result<(), NotLifted> {
        let index = self.gpr(reg)?;
        self.state.regs.insert(index, value);
        Ok(())
    }

    /// The stack pointer, as an offset from its value at entry.
    fn stack_pointer(&self) -> Result<i64, NotLifted> {
        match self.state.regs.get(&RSP).map(|value| &value.sym) {
            Some(Sym::Stack(offset)) => Ok(*offset),
            _ => Err(NotLifted::new("the stack pointer is not tracked")),
        }
    }

    fn set_stack_pointer(&mut self, offset: i64, at: u64) {
        self.state
            .regs
            .insert(RSP, Value::new(Sym::Stack(offset), 64, vec![at]));
    }

    // ---- the stack --------------------------------------------------------

    /// The slot a memory operand names, when its base is a tracked stack
    /// pointer.
    fn slot_of(&mut self, base: RegisterId, index: RegisterId, disp: i64) -> Option<i64> {
        if index.class != RC_NONE || base.class != RC_GPR {
            return None;
        }
        match self.state.regs.get(&base.index).map(|value| &value.sym) {
            Some(Sym::Stack(offset)) => Some(offset + disp),
            _ => None,
        }
    }

    /// Load `bits` bits from the slot at `offset`.
    fn load(&mut self, offset: i64, bits: u32, at: u64) -> Value {
        if let Some(slot) = self.state.stack.get(&offset) {
            if slot.bits == bits {
                return slot.value.clone().also_from(at);
            }
        }
        if self.state.overlaps(offset, bits) {
            return Value::unknown(
                format!(
                    "the {bits} bits at {} were written in parts",
                    local_name(self.options.stack_slot_names, offset)
                ),
                bits,
            );
        }
        // Never written here: the slot is a variable, read as it is.
        self.locals.entry(offset).or_insert(bits);
        let value = Value::node(
            AstNode::var(local_name(self.options.stack_slot_names, offset)),
            bits,
            vec![at],
        );
        self.state.stack.insert(
            offset,
            Slot {
                bits,
                value: value.clone(),
            },
        );
        value
    }

    /// Store `value` into the slot at `offset`.
    fn store(&mut self, offset: i64, bits: u32, value: Value, at: u64) {
        let addresses = sorted(value.from.iter().copied().chain([at]));
        let value = value.also_from(at);
        self.kill(offset, bits);
        if self.locals.contains_key(&offset) {
            // The slot is a variable: what was computed from it before this
            // store is the old value, saved into a temporary if it is in
            // memory and forgotten if it is in a register; what equals the
            // stored expression is the variable now.
            let name = local_name(self.options.stack_slot_names, offset);
            self.variable_changed(&name, &value, at);
            self.statements.push(Stmt::Store {
                offset,
                bits,
                value,
                addresses,
            });
            self.state.stack.insert(
                offset,
                Slot {
                    bits,
                    value: Value::node(AstNode::var(name), bits, vec![at]),
                },
            );
            return;
        }
        self.state.stack.insert(
            offset,
            Slot {
                bits,
                value: value.clone(),
            },
        );
        self.statements.push(Stmt::Store {
            offset,
            bits,
            value,
            addresses,
        });
    }

    /// The variable `name` is assigned `value` at `at`. What was computed
    /// from the variable before is the old value now: a register that holds
    /// the very expression assigned (`eax` after `add eax, 1; mov [x], eax`)
    /// holds the variable; another register computed from it is forgotten;
    /// a slot computed from it is saved into a temporary first. What does
    /// not read the variable is unaffected.
    fn variable_changed(&mut self, name: &str, value: &Value, at: u64) {
        let stored = match &value.sym {
            Sym::Node(node) if node.reads_var(name) => Some(node),
            _ => None,
        };
        for (&index, held) in self.state.regs.iter_mut() {
            let Sym::Node(node) = &held.sym else {
                continue;
            };
            if Some(node) == stored {
                *held = Value::node(AstNode::var(name), held.bits, held.from.clone());
            } else if node.reads_var(name) {
                *held = Value::unknown(
                    format!(
                        "{} was computed from {name} before it changed at {at:#x}",
                        gpr_name(index, held.bits)
                    ),
                    held.bits,
                );
            }
        }
        let mut stale: Vec<i64> = Vec::new();
        for (&offset, slot) in self.state.stack.iter_mut() {
            let Sym::Node(node) = &slot.value.sym else {
                continue;
            };
            if Some(node) == stored {
                slot.value = Value::node(AstNode::var(name), slot.bits, slot.value.from.clone());
            } else if node.reads_var(name) {
                stale.push(offset);
            }
        }
        for offset in stale {
            let slot = self.state.stack.get(&offset).expect("found above").clone();
            let temp = format!("v{}", self.temps.len() + self.saved.len() + 1);
            self.saved.push(Variable {
                ty: type_name(slot.bits).to_string(),
                name: temp.clone(),
            });
            self.statements.push(Stmt::Assign {
                lhs: AstNode::var(temp.clone()),
                value: slot.value.clone(),
                addresses: sorted(slot.value.from.iter().copied()),
            });
            self.state.stack.insert(
                offset,
                Slot {
                    bits: slot.bits,
                    value: Value::node(AstNode::var(temp), slot.bits, slot.value.from),
                },
            );
        }
        if self.state.flags.as_ref().is_some_and(|flags| {
            let reads = |value: &Value| value.reads_var(name);
            match &flags.producer {
                Producer::Cmp(lhs, rhs) | Producer::Test(lhs, rhs) => reads(lhs) || reads(rhs),
                Producer::Result(value) => reads(value),
            }
        }) {
            self.state.flags = None;
        }
    }

    /// Forget every slot that overlaps the `bits` bits at `offset`.
    fn kill(&mut self, offset: i64, bits: u32) {
        let end = offset + i64::from(bits / 8);
        self.state.stack.retain(|&start, slot| {
            let slot_end = start + i64::from(slot.bits / 8);
            !(start < end && offset < slot_end)
        });
    }

    /// Make the slot at `offset` a variable whose address is taken.
    fn take_address(&mut self, offset: i64) -> AstNode {
        self.address_taken.insert(offset);
        let bits = self.state.stack.get(&offset).map_or(64, |slot| slot.bits);
        self.locals.entry(offset).or_insert(bits);
        AstNode::AddressOf {
            target: Box::new(AstNode::var(local_name(
                self.options.stack_slot_names,
                offset,
            ))),
        }
    }

    /// Memory the lifter does not track was written, by a call or a store
    /// through a pointer: the slots whose address is taken are whatever is
    /// in them now, and every value read from memory is stale.
    fn memory_written(&mut self, what: &str, at: u64) {
        for &offset in &self.address_taken {
            if let Some(slot) = self.state.stack.get_mut(&offset) {
                slot.value = Value::node(
                    AstNode::var(local_name(self.options.stack_slot_names, offset)),
                    slot.bits,
                    vec![at],
                );
            }
        }
        let globals = &self.globals;
        let from_memory = |value: &Value| match &value.sym {
            Sym::Node(node) => node.any(&|n| match n {
                AstNode::Deref { .. } => true,
                AstNode::Var { name } => globals.contains(name),
                _ => false,
            }),
            _ => false,
        };
        for (&index, held) in self.state.regs.iter_mut() {
            if from_memory(held) {
                *held = Value::unknown(
                    format!(
                        "{} was read from memory before {what} at {at:#x}",
                        gpr_name(index, held.bits)
                    ),
                    held.bits,
                );
            }
        }
        for (&offset, slot) in self.state.stack.iter_mut() {
            if self.address_taken.contains(&offset) {
                continue;
            }
            if from_memory(&slot.value) {
                slot.value = Value::unknown(
                    format!(
                        "{} was read from memory before {what} at {at:#x}",
                        local_name(self.options.stack_slot_names, offset)
                    ),
                    slot.bits,
                );
            }
        }
    }

    // ---- operands ---------------------------------------------------------

    /// The value of a source operand, read at `bits` bits.
    fn value_of(&mut self, op: &Operand, bits: u32, ins: &DecodedInsn) -> Result<Value, NotLifted> {
        match *op {
            Operand::Register(reg) => self.read(reg, ins.address),
            Operand::Imm(imm) => Ok(Value::node(constant(imm, bits), bits, vec![ins.address])),
            Operand::Mem {
                base,
                index,
                scale,
                disp,
                ..
            } => match self.slot_of(base, index, disp) {
                Some(offset) => Ok(self.load(offset, bits, ins.address)),
                None => self.load_through(base, index, scale, disp, bits, ins),
            },
        }
    }

    /// Write `value` to a destination operand.
    fn assign(
        &mut self,
        op: &Operand,
        bits: u32,
        value: Value,
        ins: &DecodedInsn,
    ) -> Result<(), NotLifted> {
        match *op {
            Operand::Register(reg) => self.write(reg, value),
            Operand::Mem {
                base,
                index,
                scale,
                disp,
                ..
            } => match self.slot_of(base, index, disp) {
                Some(offset) => {
                    self.store(offset, bits, value, ins.address);
                    Ok(())
                }
                None => self.store_through(base, index, scale, disp, bits, value, ins),
            },
            Operand::Imm(_) => Err(NotLifted::new("a write to an immediate")),
        }
    }

    /// The address a memory operand names, computed at `bits` bits: the
    /// constant of an absolute or instruction-relative operand, else the
    /// base plus the scaled index plus the displacement.
    fn address_of(
        &mut self,
        base: RegisterId,
        index: RegisterId,
        scale: u32,
        disp: i64,
        bits: u32,
        ins: &DecodedInsn,
    ) -> Result<Value, NotLifted> {
        let at = ins.address;
        if base.class == RC_IP || (base.class == RC_NONE && index.class == RC_NONE) {
            let target = ins.memory_address().unwrap_or(disp as u64);
            return Ok(Value::node(
                AstNode::constant(target & mask(bits), bits / 8),
                bits,
                vec![at],
            ));
        }
        let mut address = if base.class == RC_GPR {
            self.read(RegisterId::new(RC_GPR, base.index, bits), at)?
        } else if base.class == RC_NONE {
            Value::node(constant(0, bits), bits, vec![at])
        } else {
            return Err(NotLifted::new("a memory operand with a segment base"));
        };
        if index.class != RC_NONE {
            if index.class != RC_GPR {
                return Err(NotLifted::new(
                    "a memory operand with an index that is not a general register",
                ));
            }
            let mut scaled = self.read(RegisterId::new(RC_GPR, index.index, bits), at)?;
            if scale > 1 {
                let factor = Value::node(constant(i128::from(scale), bits), bits, vec![at]);
                scaled = self.arith(BinaryOp::Mul, scaled, factor, bits, at)?;
            }
            address = self.arith(BinaryOp::Add, address, scaled, bits, at)?;
        }
        if disp != 0 {
            let offset = Value::node(constant(i128::from(disp), bits), bits, vec![at]);
            address = self.arith(BinaryOp::Add, address, offset, bits, at)?;
        }
        Ok(address)
    }

    /// The place a memory operand that is not a stack slot names: the
    /// global the image names at a constant address, else `*(T *)address`.
    fn place(&mut self, address: &Value, bits: u32) -> Result<Option<AstNode>, NotLifted> {
        if let Sym::Node(AstNode::Constant { value: target, .. }) = &address.sym {
            let pointee = match self.options.pointer_loads {
                PointerLoads::Named => self.symbols.pointee(*target),
                PointerLoads::Cast => None,
            };
            if let Some(Pointee::Data(name)) = pointee {
                if !name.is_empty() {
                    self.globals.insert(name.clone());
                    return Ok(Some(AstNode::var(name)));
                }
            }
        }
        let pointer = match &address.sym {
            Sym::Node(node) => node.clone(),
            Sym::Temp(_) => {
                let value = self.at_width(address.clone(), 64, RAX, 0)?;
                self.node_of(&value)?
            }
            Sym::Unknown(_) | Sym::Stack(_) | Sym::Entry(_) => return Ok(None),
        };
        Ok(Some(AstNode::Deref {
            target: Box::new(AstNode::Cast {
                ty: format!("{} *", type_name(bits)),
                target: Box::new(pointer),
            }),
        }))
    }

    /// A load through a pointer or from an address.
    fn load_through(
        &mut self,
        base: RegisterId,
        index: RegisterId,
        scale: u32,
        disp: i64,
        bits: u32,
        ins: &DecodedInsn,
    ) -> Result<Value, NotLifted> {
        let address = self.address_of(base, index, scale, disp, 64, ins)?;
        let from = sorted(address.from.iter().copied().chain([ins.address]));
        match self.place(&address, bits)? {
            Some(node) => Ok(Value::node(node, bits, from)),
            None => Ok(Value::unknown(
                match &address.sym {
                    Sym::Unknown(reason) => reason.clone(),
                    Sym::Entry(index) => {
                        format!("{} is read before it is written", gpr_name(*index, 64))
                    }
                    _ => format!("a load relative to the stack pointer at {:#x}", ins.address),
                },
                bits,
            )),
        }
    }

    /// A store through a pointer or to an address.
    #[allow(clippy::too_many_arguments)]
    fn store_through(
        &mut self,
        base: RegisterId,
        index: RegisterId,
        scale: u32,
        disp: i64,
        bits: u32,
        value: Value,
        ins: &DecodedInsn,
    ) -> Result<(), NotLifted> {
        let at = ins.address;
        let address = self.address_of(base, index, scale, disp, 64, ins)?;
        let Some(lhs) = self.place(&address, bits)? else {
            return Err(match &address.sym {
                Sym::Unknown(reason) => NotLifted::new(reason.clone()),
                Sym::Entry(index) => NotLifted::new(format!(
                    "{} is read before it is written",
                    gpr_name(*index, 64)
                )),
                _ => NotLifted::new(format!("a store relative to the stack pointer at {at:#x}")),
            });
        };
        let addresses = sorted(value.from.iter().chain(&address.from).copied().chain([at]));
        let value = value.also_from(at);
        // The stored value must be known now: it is in memory from here on.
        self.node_of(&value)?;
        self.statements.push(Stmt::Assign {
            lhs,
            value,
            addresses,
        });
        self.memory_written("the store", at);
        Ok(())
    }

    /// The expression a value stands for, when it is known.
    fn node_of(&mut self, value: &Value) -> Result<AstNode, NotLifted> {
        match &value.sym {
            Sym::Node(node) => Ok(node.clone()),
            Sym::Stack(offset) => Ok(self.take_address(*offset)),
            Sym::Temp(temp) => {
                let temp = &mut self.temps[*temp];
                temp.bits.get_or_insert(value.bits);
                Ok(AstNode::var(temp.name.clone()))
            }
            Sym::Entry(index) => Err(NotLifted::new(format!(
                "{} is read before it is written",
                gpr_name(*index, 64)
            ))),
            Sym::Unknown(reason) => Err(NotLifted::new(reason.clone())),
        }
    }

    /// `lhs op rhs` at `bits` bits.
    fn arith(
        &mut self,
        op: BinaryOp,
        lhs: Value,
        rhs: Value,
        bits: u32,
        at: u64,
    ) -> Result<Value, NotLifted> {
        let from = sorted(lhs.from.iter().chain(&rhs.from).copied().chain([at]));
        // Stack-pointer arithmetic keeps the pointer tracked.
        if let (Sym::Stack(offset), Sym::Node(AstNode::Constant { value, .. })) =
            (&lhs.sym, &rhs.sym)
        {
            let delta = signed(*value, bits);
            let offset = match op {
                BinaryOp::Add => offset + delta,
                BinaryOp::Sub => offset - delta,
                _ => {
                    return Ok(Value::unknown(
                        format!("the stack pointer after {} at {at:#x}", op_name(op)),
                        bits,
                    ))
                }
            };
            return Ok(Value::new(Sym::Stack(offset), bits, from));
        }
        match (&lhs.sym, &rhs.sym) {
            (Sym::Unknown(reason), _) | (_, Sym::Unknown(reason)) => {
                return Ok(Value::unknown(reason.clone(), bits))
            }
            (Sym::Stack(_), _) | (_, Sym::Stack(_)) => {
                return Ok(Value::unknown(
                    format!("arithmetic on the stack pointer at {at:#x}"),
                    bits,
                ))
            }
            _ => {}
        }
        let lhs = self.node_of(&lhs)?;
        let rhs = self.node_of(&rhs)?;
        Ok(Value::node(
            binary(op, lhs, rhs, bits, self.options.operand_order),
            bits,
            from,
        ))
    }

    /// Record what set the flags.
    fn set_flags(&mut self, producer: Producer, bits: u32, ins: &DecodedInsn) {
        self.state.flags = Some(Flags {
            producer,
            bits,
            at: ins.address,
            mnemonic: mnemonic_name(ins),
        });
    }

    // ---- instructions -----------------------------------------------------

    fn step(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let mnemonic = Mnemonic::try_from(ins.mnemonic as usize).unwrap_or(Mnemonic::INVALID);
        match mnemonic {
            Mnemonic::Nop | Mnemonic::Endbr64 => Ok(()),
            Mnemonic::Cmp => self.compare_op(false, ins),
            Mnemonic::Test => self.compare_op(true, ins),
            Mnemonic::Mov => self.mov(ins),
            Mnemonic::Movsx | Mnemonic::Movsxd => self.extend(true, ins),
            Mnemonic::Movzx => self.extend(false, ins),
            Mnemonic::Cdqe => self.cdqe(ins),
            Mnemonic::Add => self.binary_op(BinaryOp::Add, ins),
            Mnemonic::Sub => self.binary_op(BinaryOp::Sub, ins),
            Mnemonic::And => self.binary_op(BinaryOp::And, ins),
            Mnemonic::Or => self.binary_op(BinaryOp::Or, ins),
            Mnemonic::Xor => self.binary_op(BinaryOp::Xor, ins),
            Mnemonic::Imul => self.imul(ins),
            Mnemonic::Inc => self.step_by(BinaryOp::Add, ins),
            Mnemonic::Dec => self.step_by(BinaryOp::Sub, ins),
            Mnemonic::Lea => self.lea(ins),
            Mnemonic::Push => self.push(ins),
            Mnemonic::Pop => self.pop(ins),
            Mnemonic::Leave => self.leave(ins),
            Mnemonic::Call => self.call(ins),
            Mnemonic::Ret => self.ret(ins),
            _ => Err(NotLifted::new(mnemonic_name(ins))),
        }
    }

    /// The two operands of an instruction, and the width of the first.
    fn two<'i>(&self, ins: &'i DecodedInsn) -> Result<(&'i Operand, &'i Operand, u32), NotLifted> {
        let [dest, src] = ins.operands.as_slice() else {
            return Err(NotLifted::new(format!(
                "{} with {} operands",
                mnemonic_name(ins),
                ins.operands.len()
            )));
        };
        let bits = width_of(dest)
            .or_else(|| width_of(src))
            .ok_or_else(|| NotLifted::new(format!("{} with no width", mnemonic_name(ins))))?;
        Ok((dest, src, bits))
    }

    fn mov(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let (dest, src, bits) = self.two(ins)?;
        let value = self.value_of(src, bits, ins)?.also_from(ins.address);
        self.assign(dest, bits, value, ins)
    }

    /// `movsx`, `movsxd` and `movzx`: the source at its own width, widened
    /// with its sign or with zeros to the destination's.
    fn extend(&mut self, sign: bool, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let (dest, src, to) = self.two(ins)?;
        let from = width_of(src).ok_or_else(|| {
            NotLifted::new(format!("{} with no source width", mnemonic_name(ins)))
        })?;
        let value = self.value_of(src, from, ins)?;
        let widened = self.widen(value, from, to, sign, ins.address)?;
        self.assign(dest, to, widened, ins)
    }

    /// `cdqe`: `rax` is `eax` with its sign.
    fn cdqe(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let value = self.read(RegisterId::new(RC_GPR, RAX, 32), ins.address)?;
        let widened = self.widen(value, 32, 64, true, ins.address)?;
        self.state.regs.insert(RAX, widened);
        Ok(())
    }

    /// `value`, `from` bits wide, widened to `to` bits with its sign or with
    /// zeros: a cast through the signed or the unsigned narrow type.
    fn widen(
        &mut self,
        value: Value,
        from: u32,
        to: u32,
        sign: bool,
        at: u64,
    ) -> Result<Value, NotLifted> {
        let addresses = sorted(value.from.iter().copied().chain([at]));
        if let Sym::Unknown(reason) = &value.sym {
            return Ok(Value::unknown(reason.clone(), to));
        }
        let node = self.node_of(&value)?;
        let node = match node {
            AstNode::Constant { value, .. } => {
                let widened = if sign {
                    (signed(value, from) as u64) & mask(to)
                } else {
                    value & mask(from)
                };
                AstNode::constant(widened, to / 8)
            }
            node if sign => AstNode::Cast {
                ty: type_name(to).to_string(),
                target: Box::new(node),
            },
            node => cast(node, from, to),
        };
        Ok(Value::node(node, to, addresses))
    }

    fn binary_op(&mut self, op: BinaryOp, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let (dest, src, bits) = self.two(ins)?;
        // `xor eax, eax` and `sub eax, eax` are how a register is zeroed.
        if matches!(op, BinaryOp::Xor | BinaryOp::Sub) && dest == src {
            let zero = Value::node(AstNode::constant(0, bits / 8), bits, vec![ins.address]);
            self.set_flags(Producer::Result(zero.clone()), bits, ins);
            return self.assign(dest, bits, zero, ins);
        }
        let lhs = self.value_of(dest, bits, ins)?;
        let rhs = self.value_of(src, bits, ins)?;
        let result = self.arith(op, lhs, rhs, bits, ins.address)?;
        self.set_flags(Producer::Result(result.clone()), bits, ins);
        self.assign(dest, bits, result, ins)
    }

    /// `inc` and `dec`: the operand plus or minus one.
    fn step_by(&mut self, op: BinaryOp, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let [dest] = ins.operands.as_slice() else {
            return Err(NotLifted::new(format!(
                "{} with no operand",
                mnemonic_name(ins)
            )));
        };
        let bits = width_of(dest)
            .ok_or_else(|| NotLifted::new(format!("{} with no width", mnemonic_name(ins))))?;
        let lhs = self.value_of(dest, bits, ins)?;
        let one = Value::node(constant(1, bits), bits, vec![ins.address]);
        let result = self.arith(op, lhs, one, bits, ins.address)?;
        self.set_flags(Producer::Result(result.clone()), bits, ins);
        self.assign(dest, bits, result, ins)
    }

    /// `imul dest, src` and `imul dest, src, imm`. The flags it sets say
    /// only whether the product overflowed, which no condition here reads.
    fn imul(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let (dest, lhs, rhs) = match ins.operands.as_slice() {
            [dest, src] => (dest, dest, src),
            [dest, lhs, rhs] => (dest, lhs, rhs),
            _ => {
                return Err(NotLifted::new(format!(
                    "imul with {} operands",
                    ins.operands.len()
                )))
            }
        };
        let bits = width_of(dest).ok_or_else(|| NotLifted::new("imul with no width"))?;
        let lhs = self.value_of(lhs, bits, ins)?;
        let rhs = self.value_of(rhs, bits, ins)?;
        let result = self.arith(BinaryOp::Mul, lhs, rhs, bits, ins.address)?;
        self.state.flags = None;
        self.assign(dest, bits, result, ins)
    }

    /// `cmp` and `test`: nothing is written, the flags remember the
    /// operands.
    fn compare_op(&mut self, test: bool, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let (dest, src, bits) = self.two(ins)?;
        let lhs = self.value_of(dest, bits, ins)?.also_from(ins.address);
        let rhs = self.value_of(src, bits, ins)?.also_from(ins.address);
        if self.options.dead_compares == DeadCompares::Keep
            && lhs.is_expression()
            && rhs.is_expression()
        {
            // Kept as a statement until a branch reads the flags, which
            // removes it again; one no branch reads stays.
            let addresses = sorted(lhs.from.iter().chain(&rhs.from).copied());
            self.statements.push(Stmt::Compare {
                name: if test { "__test" } else { "__cmp" },
                lhs: lhs.clone(),
                rhs: rhs.clone(),
                addresses,
            });
            self.pending_compare = Some((ins.address, self.statements.len() - 1));
        }
        let producer = if test {
            Producer::Test(lhs, rhs)
        } else {
            Producer::Cmp(lhs, rhs)
        };
        self.set_flags(producer, bits, ins);
        Ok(())
    }

    /// The condition under which the conditional jump `ins` is taken, and
    /// the addresses it and its flags came from.
    fn condition(&mut self, ins: &DecodedInsn) -> Result<(AstNode, Vec<u64>), NotLifted> {
        let at = ins.address;
        let jcc = mnemonic_name(ins);
        let Some(flags) = self.state.flags.clone() else {
            return Err(NotLifted::new(format!(
                "the {jcc} at {at:#x} reads flags that nothing tracked set"
            )));
        };
        let mnemonic = Mnemonic::try_from(ins.mnemonic as usize).unwrap_or(Mnemonic::INVALID);
        let cc = match mnemonic {
            Mnemonic::Je => Cc::E,
            Mnemonic::Jne => Cc::Ne,
            Mnemonic::Jl => Cc::L,
            Mnemonic::Jge => Cc::Ge,
            Mnemonic::Jle => Cc::Le,
            Mnemonic::Jg => Cc::G,
            Mnemonic::Jb => Cc::B,
            Mnemonic::Jae => Cc::Ae,
            Mnemonic::Jbe => Cc::Be,
            Mnemonic::Ja => Cc::A,
            Mnemonic::Js => Cc::S,
            Mnemonic::Jns => Cc::Ns,
            _ => return Err(NotLifted::new(jcc.clone())),
        };
        // The compare has a consumer now: the statement kept for it goes.
        if let Some((produced, index)) = self.pending_compare {
            if produced == flags.at && index < self.statements.len() {
                self.statements.remove(index);
            }
            self.pending_compare = None;
        }
        let bits = flags.bits;
        let zero = AstNode::constant(0, bits / 8);
        let unfit = || NotLifted::new(format!("{jcc} after {} at {:#x}", flags.mnemonic, flags.at));
        let mut addresses = vec![at, flags.at];
        let node = match &flags.producer {
            Producer::Cmp(lhs, rhs) => {
                addresses.extend(lhs.from.iter().chain(&rhs.from).copied());
                let l = self.node_of(lhs)?;
                let r = self.node_of(rhs)?;
                let signed_op = |op| AstNode::binary(l.clone(), op, r.clone());
                let unsigned_op = |op| match self.options.unsigned_compare {
                    UnsignedCompare::Cast => {
                        AstNode::binary(unsigned(l.clone(), bits), op, unsigned(r.clone(), bits))
                    }
                    UnsignedCompare::Bare => signed_op(op),
                };
                match cc {
                    Cc::E => signed_op(BinaryOp::Equal),
                    Cc::Ne => signed_op(BinaryOp::NotEqual),
                    Cc::L => signed_op(BinaryOp::Less),
                    Cc::Ge => signed_op(BinaryOp::GreaterEqual),
                    Cc::Le => signed_op(BinaryOp::LessEqual),
                    Cc::G => signed_op(BinaryOp::Greater),
                    Cc::B => unsigned_op(BinaryOp::Less),
                    Cc::Ae => unsigned_op(BinaryOp::GreaterEqual),
                    Cc::Be => unsigned_op(BinaryOp::LessEqual),
                    Cc::A => unsigned_op(BinaryOp::Greater),
                    Cc::S | Cc::Ns => return Err(unfit()),
                }
            }
            Producer::Test(lhs, rhs) => {
                addresses.extend(lhs.from.iter().chain(&rhs.from).copied());
                let l = self.node_of(lhs)?;
                let r = self.node_of(rhs)?;
                if l == r {
                    let op = match cc {
                        Cc::E => BinaryOp::Equal,
                        Cc::Ne => BinaryOp::NotEqual,
                        Cc::S | Cc::L => BinaryOp::Less,
                        Cc::Ns | Cc::Ge => BinaryOp::GreaterEqual,
                        Cc::Le => BinaryOp::LessEqual,
                        Cc::G => BinaryOp::Greater,
                        Cc::B | Cc::Ae | Cc::Be | Cc::A => return Err(unfit()),
                    };
                    AstNode::binary(l, op, zero)
                } else {
                    let op = match cc {
                        Cc::E => BinaryOp::Equal,
                        Cc::Ne => BinaryOp::NotEqual,
                        _ => return Err(unfit()),
                    };
                    AstNode::binary(AstNode::binary(l, BinaryOp::And, r), op, zero)
                }
            }
            Producer::Result(value) => {
                addresses.extend(value.from.iter().copied());
                let result = self.node_of(value)?;
                let op = match cc {
                    Cc::E => BinaryOp::Equal,
                    Cc::Ne => BinaryOp::NotEqual,
                    Cc::S => BinaryOp::Less,
                    Cc::Ns => BinaryOp::GreaterEqual,
                    _ => return Err(unfit()),
                };
                AstNode::binary(result, op, zero)
            }
        };
        Ok((node, sorted(addresses)))
    }

    fn lea(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let (dest, src, bits) = self.two(ins)?;
        let Operand::Mem {
            base,
            index,
            scale,
            disp,
            ..
        } = *src
        else {
            return Err(NotLifted::new("lea of a register"));
        };
        let at = ins.address;
        let address = if base.class == RC_IP {
            // The address is the instruction's: what it names is data, and
            // the image may know what.
            let target = ins.memory_address().unwrap_or(disp as u64);
            let node = match self.symbols.pointee(target) {
                Some(Pointee::String(text)) => AstNode::StringLiteral { text },
                Some(Pointee::Data(name)) if !name.is_empty() => AstNode::AddressOf {
                    target: Box::new(AstNode::var(name)),
                },
                Some(Pointee::Function(name)) => AstNode::FunctionName {
                    name,
                    address: target,
                },
                Some(Pointee::Data(_)) | None => AstNode::constant(target, bits / 8),
            };
            Value::node(node, bits, vec![at])
        } else {
            self.address_of(base, index, scale, disp, bits, ins)?
        };
        self.assign(dest, bits, address.also_from(at), ins)
    }

    fn push(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let [src] = ins.operands.as_slice() else {
            return Err(NotLifted::new("push with no operand"));
        };
        if width_of(src).is_some_and(|bits| bits != 64) {
            return Err(NotLifted::new("a push that is not 64 bits wide"));
        }
        let value = self.value_of(src, 64, ins)?;
        let offset = self.stack_pointer()? - 8;
        self.set_stack_pointer(offset, ins.address);
        self.store(offset, 64, value, ins.address);
        Ok(())
    }

    fn pop(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let [dest] = ins.operands.as_slice() else {
            return Err(NotLifted::new("pop with no operand"));
        };
        if width_of(dest) != Some(64) {
            return Err(NotLifted::new("a pop that is not 64 bits wide"));
        }
        let offset = self.stack_pointer()?;
        let value = self.load(offset, 64, ins.address);
        self.set_stack_pointer(offset + 8, ins.address);
        self.assign(dest, 64, value, ins)
    }

    fn leave(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        // `leave` is `mov rsp, rbp; pop rbp`.
        let frame = self.read(RegisterId::new(RC_GPR, RBP, 64), ins.address)?;
        self.state.regs.insert(RSP, frame);
        let offset = self.stack_pointer()?;
        let value = self.load(offset, 64, ins.address);
        self.set_stack_pointer(offset + 8, ins.address);
        self.state.regs.insert(RBP, value);
        Ok(())
    }

    fn call(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let Flow::Call(target) = ins.flow else {
            return Err(NotLifted::new("an indirect call"));
        };
        let at = ins.address;
        let mut args = Vec::new();
        let mut addresses = vec![at];
        for &register in self.abi.argument_registers() {
            // An argument register not written in the block is not known to
            // be an argument: the list stops there.
            let Some(value) = self.state.regs.get(&register).cloned() else {
                break;
            };
            if matches!(value.sym, Sym::Unknown(_)) {
                break;
            }
            let value = self.at_width(value.clone(), value.bits, register, at)?;
            addresses.extend(value.from.iter().copied());
            args.push(self.node_of(&value)?);
        }
        let name = self
            .symbols
            .function_name(target)
            .unwrap_or_else(|| format!("sub_{target:x}"));
        let node = AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name,
                address: target,
            }),
            args,
        };
        // The call clobbers the caller-saved registers, the flags, and
        // anything in memory it can reach.
        for index in 0..16 {
            if !self.abi.is_callee_saved(index) {
                self.state.regs.insert(
                    index,
                    Value::unknown(
                        format!("{} after the call at {at:#x}", gpr_name(index, 64)),
                        64,
                    ),
                );
            }
        }
        self.state.flags = None;
        let temp = self.temps.len() + self.saved.len();
        self.temps.push(Temp {
            name: format!("v{}", temp + 1),
            bits: None,
        });
        let temp = self.temps.len() - 1;
        self.state
            .regs
            .insert(RAX, Value::new(Sym::Temp(temp), 64, vec![at]));
        self.memory_written("the call", at);
        self.statements.push(Stmt::Call {
            temp,
            node,
            addresses: sorted(addresses),
        });
        Ok(())
    }

    fn ret(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        if self.stack_pointer()? != 0 {
            return Err(NotLifted::new("the stack is not balanced at ret"));
        }
        let at = ins.address;
        let value = match self.state.regs.get(&RAX).cloned() {
            None => None,
            Some(value) => {
                let bits = match value.sym {
                    Sym::Temp(temp) => self.temps[temp].bits.unwrap_or(64),
                    _ => value.bits,
                };
                Some(self.at_width(value, bits, RAX, at)?)
            }
        };
        let mut addresses = vec![at];
        if let Some(value) = &value {
            addresses.extend(value.from.iter().copied());
        }
        let bits = value.as_ref().map(|value| value.bits);
        match self.returns {
            None => self.returns = Some(bits),
            Some(known) if known == bits => {}
            Some(Some(known)) => {
                return Err(NotLifted::new(match bits {
                    Some(bits) => format!("returns {known} bits at one ret and {bits} at another"),
                    None => "returns a value at one ret and nothing at another".to_string(),
                }))
            }
            Some(None) => {
                return Err(NotLifted::new(
                    "returns a value at one ret and nothing at another",
                ))
            }
        }
        self.statements.push(Stmt::Return {
            value,
            addresses: sorted(addresses),
        });
        Ok(())
    }

    // ---- the function -----------------------------------------------------

    /// Resolve the statements of every chain to nodes: the stores to the
    /// slots that are variables kept, the call results inlined where they
    /// are used once by the next statement and declared where they are
    /// used more.
    fn resolve_all(
        &mut self,
        chains: &[Chain],
        lifted: Vec<(Vec<Stmt>, Terminator)>,
    ) -> Result<Vec<Node>, NotLifted> {
        // Resolving a statement can take the address of a slot — a pointer
        // into the frame reaching a call or the return — which makes the
        // stores to it statements too, so this runs until no more
        // addresses are taken.
        let resolved: Vec<Vec<Resolved>> = loop {
            let taken = self.address_taken.len();
            let resolved = lifted
                .iter()
                .map(|(statements, _)| self.resolve(statements))
                .collect::<Result<Vec<_>, _>>()?;
            if self.address_taken.len() == taken {
                break resolved;
            }
        };

        let all: Vec<&Resolved> = resolved.iter().flatten().collect();
        let mut declared: Vec<Variable> = Vec::new();
        let mut nodes = Vec::new();
        for ((chain, statements), (_, terminator)) in chains.iter().zip(&resolved).zip(&lifted) {
            let mut body: Vec<Statement> = Vec::new();
            let mut pending: Option<(usize, AstNode, Vec<u64>)> = None;
            for (i, (temp, node, addresses)) in statements.iter().enumerate() {
                let mut node = node.clone();
                let mut addresses = addresses.clone();
                if let Some((temp, call, call_addresses)) = pending.take() {
                    let name = self.temps[temp].name.clone();
                    if node.reads_var(&name) {
                        node = node.substitute(&name, &call);
                        addresses.extend(call_addresses);
                        addresses = sorted(addresses);
                    } else {
                        unreachable!(
                            "a pending call is only kept when the next statement reads it"
                        );
                    }
                }
                match temp {
                    Some(temp) => {
                        let temp = *temp;
                        let name = self.temps[temp].name.clone();
                        let uses = all
                            .iter()
                            .filter(|(_, other, _)| other.reads_var(&name))
                            .count();
                        let next_reads = statements
                            .get(i + 1)
                            .is_some_and(|(_, next, _)| next.reads_var(&name));
                        if uses == 0 {
                            body.push(Statement::plain(node, addresses));
                        } else if uses == 1 && next_reads {
                            pending = Some((temp, node, addresses));
                        } else {
                            let bits = self.temps[temp].bits.unwrap_or(64);
                            declared.push(Variable {
                                ty: type_name(bits).to_string(),
                                name: name.clone(),
                            });
                            body.push(Statement::plain(
                                AstNode::Assign {
                                    lhs: Box::new(AstNode::var(name)),
                                    rhs: Box::new(node),
                                },
                                addresses,
                            ));
                        }
                    }
                    None => body.push(Statement::plain(node, addresses)),
                }
            }
            nodes.push(Node {
                address: chain.address,
                statements: body,
                terminator: terminator.clone(),
            });
        }
        self.declared = declared;
        Ok(nodes)
    }

    fn finish(
        self,
        name: &str,
        entry: u64,
        chains: &[Chain],
        body: Vec<Statement>,
    ) -> Result<LiftedFunction, NotLifted> {
        let count = match self.options.parameters {
            Parameters::LastRead => self.params.keys().next_back().map_or(0, |last| last + 1),
            Parameters::Convention => self.abi.argument_registers().len(),
        };
        let params = (0..count)
            .map(|position| Variable {
                ty: self
                    .params
                    .get(&position)
                    .map_or("long", |&bits| type_name(bits))
                    .to_string(),
                name: parameter_name(position),
            })
            .collect();

        // The locals nearest the frame first, then the registers that
        // became variables, then the temporaries.
        let mentioned = |name: &str| body.iter().any(|statement| statement.mentions(name));
        let mut locals: Vec<Variable> = self
            .locals
            .iter()
            .rev()
            .map(|(&offset, &bits)| Variable {
                ty: type_name(bits).to_string(),
                name: local_name(self.options.stack_slot_names, offset),
            })
            .collect();
        let mut merged: Vec<&Merged> = self.merged.values().collect();
        merged.sort_by(|a, b| a.name.cmp(&b.name));
        locals.extend(
            merged
                .into_iter()
                .filter(|merged| mentioned(&merged.name))
                .map(|merged| Variable {
                    ty: type_name(merged.bits).to_string(),
                    name: merged.name.clone(),
                }),
        );
        let mut temporaries: Vec<Variable> = self.declared.clone();
        temporaries.extend(self.saved.iter().cloned());
        temporaries
            .sort_by_key(|variable| variable.name[1..].parse::<usize>().unwrap_or(usize::MAX));
        locals.extend(temporaries);

        let mut claimed: BTreeSet<u64> = BTreeSet::new();
        for statement in &body {
            statement.claimed(&mut claimed);
        }
        let frame = sorted(
            chains
                .iter()
                .flat_map(|chain| chain.instructions.iter().map(|ins| ins.address))
                .filter(|address| !claimed.contains(address)),
        );

        Ok(LiftedFunction {
            name: name.to_string(),
            address: entry,
            return_type: self.returns.flatten().map_or("void", type_name).to_string(),
            params,
            locals,
            body,
            frame,
        })
    }
}

/// A condition code, as the conditional jumps spell it.
#[derive(Debug, Clone, Copy)]
enum Cc {
    E,
    Ne,
    L,
    Ge,
    Le,
    G,
    B,
    Ae,
    Be,
    A,
    S,
    Ns,
}

/// A statement resolved to a node: the temporary it defines, if it is a
/// call, the node, and the addresses it came from.
type Resolved = (Option<usize>, AstNode, Vec<u64>);

impl Lifter<'_> {
    /// The statements as nodes, with the stores to slots that are not
    /// variables left out.
    fn resolve(&mut self, statements: &[Stmt]) -> Result<Vec<Resolved>, NotLifted> {
        let mut resolved: Vec<Resolved> = Vec::new();
        for stmt in statements {
            match stmt {
                Stmt::Call {
                    temp,
                    node,
                    addresses,
                } => resolved.push((Some(*temp), node.clone(), addresses.clone())),
                Stmt::Store {
                    offset,
                    bits,
                    value,
                    addresses,
                } => {
                    if !self.locals.contains_key(offset) {
                        if self.locals.iter().any(|(&local, &width)| {
                            local < offset + i64::from(bits / 8)
                                && *offset < local + i64::from(width / 8)
                        }) {
                            return Err(NotLifted::new(format!(
                                "a partial write to {}",
                                local_name(self.options.stack_slot_names, *offset)
                            )));
                        }
                        continue;
                    }
                    let rhs = self.node_of(value)?;
                    let node = AstNode::Assign {
                        lhs: Box::new(AstNode::var(local_name(
                            self.options.stack_slot_names,
                            *offset,
                        ))),
                        rhs: Box::new(rhs),
                    };
                    resolved.push((None, node, addresses.clone()));
                }
                Stmt::Assign {
                    lhs,
                    value,
                    addresses,
                } => {
                    let rhs = self.node_of(value)?;
                    let node = AstNode::Assign {
                        lhs: Box::new(lhs.clone()),
                        rhs: Box::new(rhs),
                    };
                    resolved.push((None, node, addresses.clone()));
                }
                Stmt::Return { value, addresses } => {
                    let value = match value {
                        Some(value) => Some(Box::new(self.node_of(value)?)),
                        None => None,
                    };
                    resolved.push((None, AstNode::Return { value }, addresses.clone()));
                }
                Stmt::Compare {
                    name,
                    lhs,
                    rhs,
                    addresses,
                } => {
                    let args = vec![self.node_of(lhs)?, self.node_of(rhs)?];
                    let node = AstNode::Intrinsic {
                        name: name.to_string(),
                        args,
                    };
                    resolved.push((None, node, addresses.clone()));
                }
            }
        }
        Ok(resolved)
    }
}

// ---- helpers --------------------------------------------------------------

/// The C type of a width.
pub fn type_name(bits: u32) -> &'static str {
    match bits {
        8 => "char",
        16 => "short",
        32 => "int",
        _ => "long",
    }
}

/// The unsigned C type of a width.
fn unsigned_type_name(bits: u32) -> &'static str {
    match bits {
        8 => "unsigned char",
        16 => "unsigned short",
        32 => "unsigned int",
        _ => "unsigned long",
    }
}

/// `node`, written at `from` bits, read at `to` bits.
///
/// A narrower read truncates; a wider read of a 32-bit value zero-extends,
/// which in C is a cast through the unsigned type of the narrower width.
fn cast(node: AstNode, from: u32, to: u32) -> AstNode {
    if to < from {
        return AstNode::Cast {
            ty: type_name(to).to_string(),
            target: Box::new(node),
        };
    }
    AstNode::Cast {
        ty: unsigned_type_name(to).to_string(),
        target: Box::new(AstNode::Cast {
            ty: unsigned_type_name(from).to_string(),
            target: Box::new(node),
        }),
    }
}

/// `node` as the unsigned type of `bits`, for an unsigned comparison; a
/// constant is left as it is.
fn unsigned(node: AstNode, bits: u32) -> AstNode {
    if matches!(node, AstNode::Constant { .. }) {
        return node;
    }
    AstNode::Cast {
        ty: unsigned_type_name(bits).to_string(),
        target: Box::new(node),
    }
}

/// `lhs op rhs`, with a negative constant on the right folded into the
/// opposite operation: `a + -8` is `a - 8`. Under `operand-order canonical`
/// the operands of a commutative operator are put in canonical order first.
fn binary(op: BinaryOp, lhs: AstNode, rhs: AstNode, bits: u32, order: OperandOrder) -> AstNode {
    let (lhs, rhs) = match order {
        OperandOrder::Instruction => (lhs, rhs),
        OperandOrder::Canonical if commutes(op) && canonical_key(&rhs) < canonical_key(&lhs) => {
            (rhs, lhs)
        }
        OperandOrder::Canonical => (lhs, rhs),
    };
    if let AstNode::Constant { value, .. } = rhs {
        let signed = signed(value, bits);
        if signed < 0 {
            let positive = AstNode::constant(signed.unsigned_abs() & mask(bits), bits / 8);
            match op {
                BinaryOp::Add => return AstNode::binary(lhs, BinaryOp::Sub, positive),
                BinaryOp::Sub => return AstNode::binary(lhs, BinaryOp::Add, positive),
                _ => {}
            }
        }
    }
    AstNode::binary(lhs, op, rhs)
}

/// Whether `a op b` is `b op a`.
fn commutes(op: BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::Add | BinaryOp::Mul | BinaryOp::And | BinaryOp::Or | BinaryOp::Xor
    )
}

/// Where an operand sorts in canonical order: a variable by its name, a
/// cast or a dereference by what it wraps, a constant after everything, and
/// anything compound between the two, in its place.
fn canonical_key(node: &AstNode) -> (u8, String) {
    match node {
        AstNode::Var { name } | AstNode::FunctionName { name, .. } => (0, name.clone()),
        AstNode::Cast { target, .. }
        | AstNode::Deref { target }
        | AstNode::AddressOf { target } => canonical_key(target),
        AstNode::Constant { .. } => (2, String::new()),
        _ => (1, String::new()),
    }
}

/// A constant of `bits` bits.
fn constant(imm: i128, bits: u32) -> AstNode {
    AstNode::constant((imm as u64) & mask(bits), bits / 8)
}

/// The mask of the low `bits` bits.
fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// A constant of `bits` bits, read as a signed number.
pub fn signed(value: u64, bits: u32) -> i64 {
    let value = value & mask(bits);
    if bits < 64 && value & (1u64 << (bits - 1)) != 0 {
        (value as i64) - (1i64 << bits)
    } else {
        value as i64
    }
}

/// The width of an operand in bits, when it has one.
fn width_of(op: &Operand) -> Option<u32> {
    match *op {
        Operand::Register(reg) => Some(reg.bit_size),
        Operand::Mem { size, .. } if size > 0 => Some(size * 8),
        _ => None,
    }
}

/// The name of parameter `position`: `a`, `b`, … `z`, then `arg26`…
fn parameter_name(position: usize) -> String {
    if position < 26 {
        char::from(b'a' + position as u8).to_string()
    } else {
        format!("arg{position}")
    }
}

/// The name of the stack slot at `offset` from the entry stack pointer, the
/// offset spelled as `names` says.
fn local_name(names: SlotNames, offset: i64) -> String {
    let (prefix, magnitude) = if offset < 0 {
        ("local", -offset)
    } else {
        ("stack", offset)
    };
    match names {
        SlotNames::Hex => format!("{prefix}_{magnitude:x}"),
        SlotNames::Decimal => format!("{prefix}_{magnitude}"),
    }
}

/// The mnemonic of an instruction, as the listing spells it.
fn mnemonic_name(ins: &DecodedInsn) -> String {
    let mnemonic = Mnemonic::try_from(ins.mnemonic as usize).unwrap_or(Mnemonic::INVALID);
    format!("{mnemonic:?}").to_lowercase()
}

fn op_name(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "add",
        BinaryOp::Sub => "sub",
        BinaryOp::And => "and",
        BinaryOp::Or => "or",
        BinaryOp::Xor => "xor",
        BinaryOp::Mul => "mul",
        _ => "arithmetic",
    }
}

/// The name of a general register at a width.
fn gpr_name(index: u32, bits: u32) -> String {
    const NAMES: [[&str; 4]; 8] = [
        ["rax", "eax", "ax", "al"],
        ["rcx", "ecx", "cx", "cl"],
        ["rdx", "edx", "dx", "dl"],
        ["rbx", "ebx", "bx", "bl"],
        ["rsp", "esp", "sp", "spl"],
        ["rbp", "ebp", "bp", "bpl"],
        ["rsi", "esi", "si", "sil"],
        ["rdi", "edi", "di", "dil"],
    ];
    let column = match bits {
        64 => 0,
        32 => 1,
        16 => 2,
        _ => 3,
    };
    match NAMES.get(index as usize) {
        Some(names) => names[column].to_string(),
        None => format!("r{index}{}", ["", "d", "w", "b"][column]),
    }
}

/// The name of a high byte register: `ah`, `ch`, `dh`, `bh`.
fn high_byte_name(index: u32) -> &'static str {
    ["ah", "ch", "dh", "bh"]
        .get(index as usize)
        .copied()
        .unwrap_or("a high byte")
}

/// Addresses in order, each once.
fn sorted(addresses: impl IntoIterator<Item = u64>) -> Vec<u64> {
    let set: BTreeSet<u64> = addresses.into_iter().collect();
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu_context::X86IcedContext;
    use crate::emit::emit_function;

    /// The base the test code is decoded at.
    const BASE: u64 = 0x1000;

    /// Decode 64-bit code at [`BASE`].
    fn decode(bytes: &[u8]) -> Vec<DecodedInsn> {
        let mut ctx = X86IcedContext::default();
        Disasm::decode(&mut ctx, bytes, BASE)
            .expect("the code decodes")
            .instructions
    }

    /// The callee names the tests know.
    fn names(address: u64) -> Option<String> {
        match address {
            0x2000 => Some("f".to_string()),
            0x3000 => Some("g".to_string()),
            _ => None,
        }
    }

    /// Lift `bytes` as the function `f` under System V, and print it.
    fn lift(bytes: &[u8]) -> Result<LiftedFunction, NotLifted> {
        lift_block(
            &decode(bytes),
            BASE,
            "f",
            Abi::SystemV,
            &names,
            &Options::default(),
        )
    }

    /// The C of `bytes`, or the reason it was not lifted.
    fn c(bytes: &[u8]) -> String {
        match lift(bytes) {
            Ok(function) => emit_function(&function, &Options::default()).text(),
            Err(error) => error.to_string(),
        }
    }

    /// The C of `bytes` with the options `pairs` set, lifted against
    /// `symbols`, or the reason it was not lifted.
    fn c_with(bytes: &[u8], symbols: &dyn Symbols, pairs: &[(&str, &str)]) -> String {
        let options = Options::from_pairs(pairs.iter().copied()).expect("the options are known");
        match lift_block(&decode(bytes), BASE, "f", Abi::SystemV, symbols, &options) {
            Ok(function) => emit_function(&function, &options).text(),
            Err(error) => error.to_string(),
        }
    }

    /// The reason `bytes` were not lifted.
    fn refused(bytes: &[u8]) -> String {
        lift(bytes).expect_err("the code is refused").to_string()
    }

    #[test]
    fn a_parameter_register_moved_to_eax_is_returned() {
        // mov eax, edi; ret
        assert_eq!(c(&[0x89, 0xf8, 0xc3]), "int f(int a)\n{\n  return a;\n}");
    }

    #[test]
    fn a_64_bit_move_makes_the_parameter_and_the_return_long() {
        // mov rax, rdi; ret
        assert_eq!(
            c(&[0x48, 0x89, 0xf8, 0xc3]),
            "long f(long a)\n{\n  return a;\n}"
        );
    }

    #[test]
    fn an_immediate_move_is_a_constant() {
        // mov eax, 5; ret
        assert_eq!(
            c(&[0xb8, 5, 0, 0, 0, 0xc3]),
            "int f(void)\n{\n  return 5;\n}"
        );
    }

    #[test]
    fn the_second_argument_register_is_the_second_parameter() {
        // mov eax, esi; ret: rdi is never read, so `a` has no width here.
        assert_eq!(
            c(&[0x89, 0xf0, 0xc3]),
            "int f(long a, int b)\n{\n  return b;\n}"
        );
    }

    #[test]
    fn add_sub_and_or_xor_are_the_c_operators_in_operand_order() {
        // mov eax, edi; <op> eax, esi; ret
        for (opcode, operator) in [
            (0x01, "+"),
            (0x29, "-"),
            (0x21, "&"),
            (0x09, "|"),
            (0x31, "^"),
        ] {
            assert_eq!(
                c(&[0x89, 0xf8, opcode, 0xf0, 0xc3]),
                format!("int f(int a, int b)\n{{\n  return a {operator} b;\n}}")
            );
        }
    }

    #[test]
    fn an_immediate_operand_is_a_constant_and_a_negative_one_flips_the_operator() {
        // mov eax, edi; add eax, 1; ret
        assert_eq!(
            c(&[0x89, 0xf8, 0x83, 0xc0, 0x01, 0xc3]),
            "int f(int a)\n{\n  return a + 1;\n}"
        );
        // mov eax, edi; add eax, -1; ret
        assert_eq!(
            c(&[0x89, 0xf8, 0x83, 0xc0, 0xff, 0xc3]),
            "int f(int a)\n{\n  return a - 1;\n}"
        );
    }

    #[test]
    fn xor_of_a_register_with_itself_is_zero() {
        // xor eax, eax; ret
        assert_eq!(c(&[0x31, 0xc0, 0xc3]), "int f(void)\n{\n  return 0;\n}");
    }

    #[test]
    fn inc_dec_and_imul_are_arithmetic_too() {
        // mov eax, edi; inc eax; ret
        assert_eq!(
            c(&[0x89, 0xf8, 0xff, 0xc0, 0xc3]),
            "int f(int a)\n{\n  return a + 1;\n}"
        );
        // mov eax, edi; dec eax; ret
        assert_eq!(
            c(&[0x89, 0xf8, 0xff, 0xc8, 0xc3]),
            "int f(int a)\n{\n  return a - 1;\n}"
        );
        // mov eax, edi; imul eax, esi; ret
        assert_eq!(
            c(&[0x89, 0xf8, 0x0f, 0xaf, 0xc6, 0xc3]),
            "int f(int a, int b)\n{\n  return a * b;\n}"
        );
        // imul eax, edi, 3; ret
        assert_eq!(
            c(&[0x6b, 0xc7, 0x03, 0xc3]),
            "int f(int a)\n{\n  return a * 3;\n}"
        );
    }

    #[test]
    fn sign_and_zero_extensions_are_casts() {
        // mov eax, edi; cdqe; ret
        assert_eq!(
            c(&[0x89, 0xf8, 0x48, 0x98, 0xc3]),
            "long f(int a)\n{\n  return (long)a;\n}"
        );
        // movsx eax, byte [rdi]; ret
        assert_eq!(
            c(&[0x0f, 0xbe, 0x07, 0xc3]),
            "int f(long a)\n{\n  return (int)*(char *)a;\n}"
        );
        // movzx eax, byte [rdi]; ret
        assert_eq!(
            c(&[0x0f, 0xb6, 0x07, 0xc3]),
            "int f(long a)\n{\n  return (unsigned int)(unsigned char)*(char *)a;\n}"
        );
    }

    #[test]
    fn lea_of_two_registers_is_their_sum_and_a_displacement_is_added() {
        // lea eax, [rdi+rsi]; ret
        assert_eq!(
            c(&[0x8d, 0x04, 0x37, 0xc3]),
            "int f(int a, int b)\n{\n  return a + b;\n}"
        );
        // lea rax, [rdi+rsi*4+8]; ret
        assert_eq!(
            c(&[0x48, 0x8d, 0x44, 0xb7, 0x08, 0xc3]),
            "long f(long a, long b)\n{\n  return (a + (b * 4)) + 8;\n}"
        );
        // lea rax, [rdi-8]; ret
        assert_eq!(
            c(&[0x48, 0x8d, 0x47, 0xf8, 0xc3]),
            "long f(long a)\n{\n  return a - 8;\n}"
        );
    }

    #[test]
    fn lea_through_rip_is_the_address_it_names() {
        // lea rax, [rip+0x1000]; ret: the next instruction is at 0x1007.
        assert_eq!(
            c(&[0x48, 0x8d, 0x05, 0x00, 0x10, 0x00, 0x00, 0xc3]),
            "long f(void)\n{\n  return 0x2007;\n}"
        );
    }

    #[test]
    fn the_frame_pointer_prologue_and_epilogue_leave_no_statement() {
        // push rbp; mov rbp, rsp; mov eax, edi; pop rbp; ret
        let function = lift(&[0x55, 0x48, 0x89, 0xe5, 0x89, 0xf8, 0x5d, 0xc3]).expect("lifts");
        assert_eq!(
            emit_function(&function, &Options::default()).text(),
            "int f(int a)\n{\n  return a;\n}"
        );
        assert_eq!(
            function.frame,
            vec![0x1000, 0x1001, 0x1006],
            "the push, the mov rbp and the pop belong to no statement"
        );
    }

    #[test]
    fn a_value_stored_in_a_frame_slot_and_loaded_back_is_propagated() {
        // push rbp; mov rbp, rsp; mov [rbp-4], edi; mov eax, [rbp-4]; pop rbp; ret
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, 0x5d, 0xc3,
        ];
        let function = lift(&code).expect("lifts");
        assert_eq!(
            emit_function(&function, &Options::default()).text(),
            "int f(int a)\n{\n  return a;\n}"
        );
        let ret = function.body.last().expect("a return");
        assert_eq!(
            ret.addresses,
            vec![0x1004, 0x1007, 0x100b],
            "the return came from the store, the load and the ret"
        );
    }

    #[test]
    fn a_slot_below_rsp_is_a_local_too() {
        // sub rsp, 0x10; mov [rsp+8], edi; mov eax, [rsp+8]; add rsp, 0x10; ret
        let code = [
            0x48, 0x83, 0xec, 0x10, 0x89, 0x7c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0x48, 0x83,
            0xc4, 0x10, 0xc3,
        ];
        assert_eq!(c(&code), "int f(int a)\n{\n  return a;\n}");
    }

    #[test]
    fn a_slot_read_before_it_is_written_is_a_declared_local() {
        // mov eax, [rsp-8]; ret
        assert_eq!(
            c(&[0x8b, 0x44, 0x24, 0xf8, 0xc3]),
            "int f(void)\n{\n  int local_8;\n\n  return local_8;\n}"
        );
    }

    #[test]
    fn a_slot_whose_address_is_taken_keeps_its_stores() {
        // mov [rsp-8], edi; lea rax, [rsp-8]; ret
        assert_eq!(
            c(&[0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8d, 0x44, 0x24, 0xf8, 0xc3]),
            "long f(int a)\n{\n  int local_8;\n\n  local_8 = a;\n  return &local_8;\n}"
        );
    }

    #[test]
    fn a_value_copied_from_a_variable_before_it_changes_is_saved() {
        // mov eax, [rsp-8]; mov [rsp-16], eax; mov dword [rsp-8], 5;
        // mov eax, [rsp-16]; ret: the copy in the second slot is the old
        // value, which the store to the first would otherwise rewrite.
        let code = [
            0x8b, 0x44, 0x24, 0xf8, 0x89, 0x44, 0x24, 0xf0, 0xc7, 0x44, 0x24, 0xf8, 5, 0, 0, 0,
            0x8b, 0x44, 0x24, 0xf0, 0xc3,
        ];
        assert_eq!(
            c(&code),
            "int f(void)\n{\n  int local_8;\n  int v1;\n\n  v1 = local_8;\n  local_8 = 5;\n  return v1;\n}"
        );
    }

    #[test]
    fn a_push_and_a_pop_move_a_value_through_the_stack() {
        // push rdi; pop rax; ret
        assert_eq!(c(&[0x57, 0x58, 0xc3]), "long f(long a)\n{\n  return a;\n}");
    }

    #[test]
    fn a_slot_overwritten_in_parts_is_not_known() {
        // push rax; mov [rsp], edi; pop rax; ret
        assert_eq!(
            refused(&[0x50, 0x89, 0x3c, 0x24, 0x58, 0xc3]),
            "not lifted yet: the 64 bits at local_8 were written in parts"
        );
    }

    #[test]
    fn leave_tears_the_frame_down() {
        // push rbp; mov rbp, rsp; sub rsp, 0x10; mov [rbp-4], edi; mov eax, [rbp-4]; leave; ret
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc,
            0xc9, 0xc3,
        ];
        assert_eq!(c(&code), "int f(int a)\n{\n  return a;\n}");
    }

    #[test]
    fn a_call_passes_the_argument_registers_written_before_it_and_returns_rax() {
        // mov esi, 3; mov edi, edi (no-op write); call f; ret
        // mov edi, edi: 89 ff
        let code = [
            0xbe, 3, 0, 0, 0, 0x89, 0xff, 0xe8, 0xf4, 0x0f, 0x00, 0x00, 0xc3,
        ];
        assert_eq!(c(&code), "long f(int a)\n{\n  return f(a, 3);\n}");
    }

    #[test]
    fn a_call_whose_result_is_read_as_32_bits_returns_int() {
        // call f; mov eax, eax; ret
        let code = [0xe8, 0xfb, 0x0f, 0x00, 0x00, 0x89, 0xc0, 0xc3];
        assert_eq!(c(&code), "int f(void)\n{\n  return f();\n}");
    }

    #[test]
    fn a_call_result_used_later_is_a_declared_temporary() {
        // call f; mov ebx, eax; call g; add eax, ebx; ret
        let code = [
            0xe8, 0xfb, 0x0f, 0x00, 0x00, 0x89, 0xc3, 0xe8, 0xf4, 0x1f, 0x00, 0x00, 0x01, 0xd8,
            0xc3,
        ];
        assert_eq!(
            c(&code),
            "int f(void)\n{\n  int v1;\n\n  v1 = f();\n  return g() + v1;\n}"
        );
    }

    #[test]
    fn a_call_whose_result_is_dropped_is_a_statement() {
        // call f; mov eax, 0; ret
        let code = [0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xb8, 0, 0, 0, 0, 0xc3];
        assert_eq!(c(&code), "int f(void)\n{\n  f();\n  return 0;\n}");
    }

    #[test]
    fn a_call_to_an_address_with_no_name_is_sub() {
        // mov edi, 1; call 0x4000; ret
        let code = [0xbf, 1, 0, 0, 0, 0xe8, 0xf6, 0x2f, 0x00, 0x00, 0xc3];
        assert_eq!(c(&code), "long f(void)\n{\n  return sub_4000(1);\n}");
    }

    #[test]
    fn a_register_the_call_clobbered_is_not_read_after_it() {
        // mov ecx, edi; call f; mov eax, ecx; ret
        let code = [0x89, 0xf9, 0xe8, 0xf9, 0x0f, 0x00, 0x00, 0x89, 0xc8, 0xc3];
        assert_eq!(
            refused(&code),
            "not lifted yet: rcx after the call at 0x1002"
        );
    }

    #[test]
    fn a_value_read_from_memory_is_forgotten_across_a_call() {
        // mov ebx, [rdi]; call f; mov eax, ebx; ret: rbx survives the call,
        // but what it was loaded from may not.
        let code = [0x8b, 0x1f, 0xe8, 0xf9, 0x0f, 0x00, 0x00, 0x89, 0xd8, 0xc3];
        assert_eq!(
            refused(&code),
            "not lifted yet: ebx was read from memory before the call at 0x1002"
        );
    }

    #[test]
    fn a_function_that_never_writes_rax_returns_void() {
        // nop; ret
        assert_eq!(c(&[0x90, 0xc3]), "void f(void)\n{\n  return;\n}");
    }

    #[test]
    fn eax_read_as_rax_is_zero_extended_and_rax_read_as_eax_is_truncated() {
        // mov eax, edi; mov rdx, rax; mov rax, rdx; ret
        assert_eq!(
            c(&[0x89, 0xf8, 0x48, 0x89, 0xc2, 0x48, 0x89, 0xd0, 0xc3]),
            "long f(int a)\n{\n  return (unsigned long)(unsigned int)a;\n}"
        );
        // mov rdx, rdi; mov eax, edx; ret
        assert_eq!(
            c(&[0x48, 0x89, 0xfa, 0x89, 0xd0, 0xc3]),
            "int f(long a)\n{\n  return (int)a;\n}"
        );
    }

    #[test]
    fn a_16_bit_write_is_a_short_and_a_wider_read_after_it_is_not_known() {
        // mov ax, di; ret
        assert_eq!(
            c(&[0x66, 0x89, 0xf8, 0xc3]),
            "short f(short a)\n{\n  return a;\n}"
        );
        // mov ax, di; mov eax, eax; ret
        assert_eq!(
            refused(&[0x66, 0x89, 0xf8, 0x89, 0xc0, 0xc3]),
            "not lifted yet: the upper bits of eax after a 16-bit write"
        );
    }

    #[test]
    fn flag_setters_with_no_consumer_leave_no_statement() {
        // mov eax, edi; cmp eax, esi; test eax, eax; ret. The cmp reads esi,
        // which makes `b` a parameter even though nothing reads the flags.
        assert_eq!(
            c(&[0x89, 0xf8, 0x39, 0xf0, 0x85, 0xc0, 0xc3]),
            "int f(int a, int b)\n{\n  return a;\n}"
        );
    }

    #[test]
    fn endbr64_and_nop_are_dropped() {
        // endbr64; nop; mov eax, edi; ret
        assert_eq!(
            c(&[0xf3, 0x0f, 0x1e, 0xfa, 0x90, 0x89, 0xf8, 0xc3]),
            "int f(int a)\n{\n  return a;\n}"
        );
    }

    #[test]
    fn an_instruction_outside_the_set_is_refused_by_name() {
        // mov eax, edi; cwde; ret
        assert_eq!(refused(&[0x89, 0xf8, 0x98, 0xc3]), "not lifted yet: cwde");
        // div esi; ret
        assert_eq!(refused(&[0xf7, 0xf6, 0xc3]), "not lifted yet: div");
    }

    #[test]
    fn a_block_that_does_not_end_in_ret_is_refused() {
        // mov eax, edi; jmp rax
        assert_eq!(
            refused(&[0x89, 0xf8, 0xff, 0xe0]),
            "not lifted yet: the block ends in jmp"
        );
        assert_eq!(refused(&[]), "not lifted yet: no code at 0x1000");
    }

    #[test]
    fn a_load_through_a_pointer_is_a_typed_dereference() {
        // mov eax, [rdi]; ret
        assert_eq!(
            c(&[0x8b, 0x07, 0xc3]),
            "int f(long a)\n{\n  return *(int *)a;\n}"
        );
        // mov eax, [rip+0x10]; ret: an address the image does not name.
        assert_eq!(
            c(&[0x8b, 0x05, 0x10, 0, 0, 0, 0xc3]),
            "int f(void)\n{\n  return *(int *)0x1016;\n}"
        );
        // mov eax, [rdi+rsi*4+8]; ret
        assert_eq!(
            c(&[0x8b, 0x44, 0xb7, 0x08, 0xc3]),
            "int f(long a, long b)\n{\n  return *(int *)((a + (b * 4)) + 8);\n}"
        );
    }

    #[test]
    fn a_store_through_a_pointer_is_a_statement() {
        // mov [rdi], esi; ret
        assert_eq!(
            c(&[0x89, 0x37, 0xc3]),
            "void f(long a, int b)\n{\n  *(int *)a = b;\n  return;\n}"
        );
    }

    #[test]
    fn a_register_read_before_it_is_written_that_is_not_an_argument_is_refused() {
        // mov eax, ebx; ret
        assert_eq!(
            refused(&[0x89, 0xd8, 0xc3]),
            "not lifted yet: rbx is read before it is written"
        );
    }

    #[test]
    fn an_indirect_call_is_refused() {
        // call rdi; ret
        assert_eq!(
            refused(&[0xff, 0xd7, 0xc3]),
            "not lifted yet: an indirect call"
        );
    }

    #[test]
    fn an_unbalanced_stack_is_refused() {
        // push rdi; ret
        assert_eq!(
            refused(&[0x57, 0xc3]),
            "not lifted yet: the stack is not balanced at ret"
        );
    }

    #[test]
    fn the_windows_convention_takes_its_arguments_from_rcx_and_rdx() {
        // mov eax, ecx; add eax, edx; ret
        let function = lift_block(
            &decode(&[0x89, 0xc8, 0x01, 0xd0, 0xc3]),
            BASE,
            "add",
            Abi::Win64,
            &names,
            &Options::default(),
        )
        .expect("lifts");
        assert_eq!(
            emit_function(&function, &Options::default()).text(),
            "int add(int a, int b)\n{\n  return a + b;\n}"
        );
    }

    #[test]
    fn the_convention_comes_from_the_language() {
        assert_eq!(Abi::of_language("x86:LE:64:default:windows"), Abi::Win64);
        assert_eq!(Abi::of_language("x86:LE:64:default:gcc"), Abi::SystemV);
        assert_eq!(Abi::of_language("x86:LE:32:default:gcc"), Abi::SystemV);
    }

    /// Lift `bytes` as the function `f` through its control-flow graph, the
    /// way an image does, and return the graph with the answer.
    fn lift_cfg(
        bytes: &[u8],
        bitness: Bitness,
    ) -> (ProcedureCfg, Result<LiftedFunction, NotLifted>) {
        let disasm = Disasm {
            file_offset_of_segment: 0,
            instructions: decode(bytes),
        };
        let cfg = crate::cfgwalk::resolve_branches(&disasm, BASE);
        let lifted = lift_function(
            &disasm,
            &cfg,
            BASE,
            "f",
            bitness,
            Abi::SystemV,
            &names,
            &Options::default(),
        );
        (cfg, lifted)
    }

    #[test]
    fn a_chain_of_blocks_joined_by_fall_through_is_lifted_as_one() {
        // mov edi, 1; call f; mov eax, eax; ret. The walk ends a block at
        // the call, so this is two blocks, the second starting where the
        // first ends, and the state carries across: rdi was written before
        // the call, and rax is read after it.
        let code = [
            0xbf, 1, 0, 0, 0, 0xe8, 0xf6, 0x0f, 0x00, 0x00, 0x89, 0xc0, 0xc3,
        ];
        let (cfg, lifted) = lift_cfg(&code, Bitness::Bits64);
        assert_eq!(cfg.blocks.len(), 2);
        assert_eq!(cfg.blocks[0].successor_addresses, vec![0x100a]);
        let function = lifted.expect("the chain lifts");
        assert_eq!(
            emit_function(&function, &Options::default()).text(),
            "int f(void)\n{\n  return f(1);\n}"
        );

        // call f; call g; ret: three blocks, two calls, the second's
        // result returned.
        let code = [
            0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xe8, 0xf6, 0x1f, 0x00, 0x00, 0xc3,
        ];
        let (cfg, lifted) = lift_cfg(&code, Bitness::Bits64);
        assert_eq!(cfg.blocks.len(), 3);
        assert_eq!(
            emit_function(&lifted.expect("the chain lifts"), &Options::default()).text(),
            "long f(void)\n{\n  f();\n  return g();\n}"
        );
    }

    #[test]
    fn the_samples_sum_to_is_a_counted_loop() {
        // The sample's sum_to: endbr64; push rbp; mov rbp, rsp;
        // mov [rbp-0x14], edi; mov qword [rbp-8], 0; mov dword [rbp-0xc], 1;
        // jmp .test; .body: mov eax, [rbp-0xc]; cdqe; add [rbp-8], rax;
        // add dword [rbp-0xc], 1; .test: mov eax, [rbp-0xc]; cmp eax,
        // [rbp-0x14]; jle .body; mov rax, [rbp-8]; pop rbp; ret.
        let sum_to = [
            0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xec, 0x48, 0xc7, 0x45,
            0xf8, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xf4, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x0d,
            0x8b, 0x45, 0xf4, 0x48, 0x98, 0x48, 0x01, 0x45, 0xf8, 0x83, 0x45, 0xf4, 0x01, 0x8b,
            0x45, 0xf4, 0x3b, 0x45, 0xec, 0x7e, 0xeb, 0x48, 0x8b, 0x45, 0xf8, 0x5d, 0xc3,
        ];
        let (cfg, lifted) = lift_cfg(&sum_to, Bitness::Bits64);
        assert_eq!(cfg.blocks.len(), 4);
        let function = lifted.expect("the loop lifts");
        assert_eq!(
            emit_function(&function, &Options::default()).text(),
            "long f(int a)\n\
             {\n\
             \x20 long local_10;\n\
             \x20 int local_14;\n\
             \n\
             \x20 local_10 = 0;\n\
             \x20 for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) {\n\
             \x20   local_10 = local_10 + (long)local_14;\n\
             \x20 }\n\
             \x20 return local_10;\n\
             }"
        );
        let lp = &function.body[1];
        assert!(matches!(lp.kind, StatementKind::For { .. }));
        assert_eq!(
            lp.addresses,
            vec![0x1008, 0x1013, 0x101a, 0x1025, 0x1029, 0x102c, 0x102f],
            "the for line came from the init, the jump in, the step, the compare and the branch"
        );
        assert_eq!(
            function.frame,
            vec![0x1000, 0x1004, 0x1005, 0x1035],
            "endbr64, the push, the mov rbp and the pop belong to no statement"
        );
    }

    #[test]
    fn a_jump_or_a_branch_to_the_next_instruction_is_straight_line_code() {
        // mov eax, edi; test eax, eax; jz +0; ret
        let (_, lifted) = lift_cfg(&[0x89, 0xf8, 0x85, 0xc0, 0x74, 0x00, 0xc3], Bitness::Bits64);
        assert_eq!(
            emit_function(&lifted.expect("lifts"), &Options::default()).text(),
            "int f(int a)\n{\n  return a;\n}"
        );
        // jmp +0; ret
        let (cfg, lifted) = lift_cfg(&[0xeb, 0x00, 0xc3], Bitness::Bits64);
        assert_eq!(cfg.blocks.len(), 2);
        assert_eq!(
            emit_function(&lifted.expect("lifts"), &Options::default()).text(),
            "void f(void)\n{\n  return;\n}"
        );
    }

    #[test]
    fn a_diamond_merges_a_register_into_a_variable_named_after_it() {
        // cmp edi, 0; jle .else; mov eax, 1; jmp .join; .else: mov eax, 2;
        // .join: ret. The register differs where the paths join, so it is
        // declared and assigned on each.
        let code = [
            0x83, 0xff, 0x00, 0x7e, 0x07, 0xb8, 1, 0, 0, 0, 0xeb, 0x05, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        let function = lift(&code).expect("lifts");
        assert_eq!(
            emit_function(&function, &Options::default()).text(),
            "int f(int a)\n\
             {\n\
             \x20 int eax;\n\
             \n\
             \x20 if (a <= 0) {\n\
             \x20   eax = 2;\n\
             \x20 } else {\n\
             \x20   eax = 1;\n\
             \x20 }\n\
             \x20 return eax;\n\
             }"
        );
        let branch = &function.body[0];
        assert_eq!(
            branch.addresses,
            vec![0x1000, 0x1003],
            "the cmp and the jle"
        );
        let StatementKind::If { then_part, .. } = &branch.kind else {
            panic!("an if");
        };
        assert_eq!(then_part[0].addresses, vec![0x100c], "the mov eax, 2");

        // The same with an unsigned condition: cmp edi, esi; jb .else.
        let code = [
            0x39, 0xf7, 0x72, 0x07, 0xb8, 1, 0, 0, 0, 0xeb, 0x05, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        assert!(
            c(&code).contains("if ((unsigned int)a < (unsigned int)b) {"),
            "{}",
            c(&code)
        );
    }

    #[test]
    fn an_early_return_is_a_guard() {
        // test edi, edi; jne .rest; mov eax, 0; ret; .rest: mov eax, edi;
        // add eax, 1; ret
        let code = [
            0x85, 0xff, 0x75, 0x06, 0xb8, 0, 0, 0, 0, 0xc3, 0x89, 0xf8, 0x83, 0xc0, 0x01, 0xc3,
        ];
        assert_eq!(
            c(&code),
            "int f(int a)\n{\n  if (a != 0) {\n    return a + 1;\n  }\n  return 0;\n}"
        );
    }

    #[test]
    fn a_loop_in_registers_is_a_do_while_over_variables() {
        // xor eax, eax; .top: add eax, edi; sub edi, 1; jne .top; ret.
        // Both registers change round the loop, so both are variables;
        // the one the entry never wrote is the parameter there; the branch
        // reads the flags of the sub, which is the variable's new value.
        let code = [0x31, 0xc0, 0x01, 0xf8, 0x83, 0xef, 0x01, 0x75, 0xf9, 0xc3];
        assert_eq!(
            c(&code),
            "int f(int a)\n\
             {\n\
             \x20 int eax;\n\
             \x20 int edi;\n\
             \n\
             \x20 eax = 0;\n\
             \x20 edi = a;\n\
             \x20 do {\n\
             \x20   eax = eax + edi;\n\
             \x20   edi = edi - 1;\n\
             \x20 } while (edi != 0);\n\
             \x20 return eax;\n\
             }"
        );
    }

    #[test]
    fn a_loop_with_two_entries_is_irreducible_and_refused() {
        // test edi, edi; je .b; .a: jmp .b; .b: test esi, esi; jne .a; ret.
        // .a and .b each reach the other and both are entered from the top.
        let code = [
            0x85, 0xff, 0x74, 0x02, 0xeb, 0x00, 0x85, 0xf6, 0x75, 0xfa, 0xc3,
        ];
        assert_eq!(
            refused(&code),
            "not lifted yet: irreducible control flow at 0x1006"
        );
    }

    #[test]
    fn a_function_that_never_returns_is_an_endless_loop() {
        // call f; .top: jmp .top
        let code = [0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xeb, 0xfe];
        assert_eq!(c(&code), "void f(void)\n{\n  f();\n  while (1) {\n  }\n}");
    }

    #[test]
    fn a_stack_pointer_that_differs_between_paths_is_refused() {
        // test edi, edi; je .ret; push rbp; .ret: ret
        assert_eq!(
            refused(&[0x85, 0xff, 0x74, 0x01, 0x55, 0xc3]),
            "not lifted yet: the stack pointer differs at 0x1005"
        );
    }

    #[test]
    fn a_branch_whose_flags_are_not_tracked_is_refused() {
        // mov eax, edi; je .ret; mov eax, 1; .ret: ret
        assert_eq!(
            refused(&[0x89, 0xf8, 0x74, 0x05, 0xb8, 1, 0, 0, 0, 0xc3]),
            "not lifted yet: the je at 0x1002 reads flags that nothing tracked set"
        );
        // cmp edi, 0; js .ret; mov eax, 1; .ret: ret: the sign of a
        // subtraction is not a relation between the operands.
        assert_eq!(
            refused(&[0x83, 0xff, 0x00, 0x78, 0x05, 0xb8, 1, 0, 0, 0, 0xc3]),
            "not lifted yet: js after cmp at 0x1000"
        );
    }

    #[test]
    fn a_32_bit_function_is_refused_before_the_walk() {
        let (_, lifted) = lift_cfg(&[0x89, 0xf8, 0xc3], Bitness::Bits32);
        assert_eq!(
            lifted.expect_err("32-bit code is refused").to_string(),
            "not lifted yet: 32-bit code"
        );
    }

    /// An image that knows a string, a piece of data and a function.
    struct Image;

    impl Symbols for Image {
        fn function_name(&self, address: u64) -> Option<String> {
            names(address)
        }

        fn pointee(&self, address: u64) -> Option<Pointee> {
            match address {
                0x2007 => Some(Pointee::String("%ld\n".into())),
                0x3007 => Some(Pointee::Data("counter".into())),
                0x2000 => Some(Pointee::Function("f".into())),
                _ => None,
            }
        }
    }

    /// The C of `bytes` lifted against [`Image`].
    fn c_with_image(bytes: &[u8]) -> String {
        c_with(bytes, &Image, &[])
    }

    #[test]
    fn a_pointer_to_a_string_the_image_knows_is_its_literal() {
        // lea rdi, [rip+0x1000]; call f; ret: the lea is at 0x1000 and 7
        // bytes long, so it names 0x2007, which the image says is "%ld\n".
        let code = [
            0x48, 0x8d, 0x3d, 0x00, 0x10, 0x00, 0x00, 0xe8, 0xf4, 0x0f, 0x00, 0x00, 0xc3,
        ];
        assert_eq!(
            c_with_image(&code),
            "long f(void)\n{\n  return f(\"%ld\\n\");\n}"
        );
    }

    #[test]
    fn a_pointer_to_named_data_is_its_address_and_one_to_a_function_is_its_name() {
        // lea rax, [rip+0x2000]; ret: names 0x3007, the data `counter`.
        assert_eq!(
            c_with_image(&[0x48, 0x8d, 0x05, 0x00, 0x20, 0x00, 0x00, 0xc3]),
            "long f(void)\n{\n  return &counter;\n}"
        );
        // lea rax, [rip+0xff9]; ret: names 0x2000, the function `f`.
        assert_eq!(
            c_with_image(&[0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0xc3]),
            "long f(void)\n{\n  return f;\n}"
        );
        // lea rax, [rip+0x1000]; ret: names 0x2007, which the plain names
        // know nothing about, so it stays the address.
        assert_eq!(
            c(&[0x48, 0x8d, 0x05, 0x00, 0x10, 0x00, 0x00, 0xc3]),
            "long f(void)\n{\n  return 0x2007;\n}"
        );
    }

    #[test]
    fn a_load_from_named_data_is_the_name() {
        // mov eax, [rip+0x2001]; ret: the next instruction is at 0x1006, so
        // this loads 0x3007, the data `counter`.
        assert_eq!(
            c_with_image(&[0x8b, 0x05, 0x01, 0x20, 0x00, 0x00, 0xc3]),
            "int f(void)\n{\n  return counter;\n}"
        );
    }

    #[test]
    fn the_signature_line_stands_for_the_entry_and_the_frame() {
        // push rbp; mov rbp, rsp; mov eax, edi; pop rbp; ret
        let function = lift(&[0x55, 0x48, 0x89, 0xe5, 0x89, 0xf8, 0x5d, 0xc3]).expect("lifts");
        let pseudocode = emit_function(&function, &Options::default());
        assert_eq!(pseudocode.lines[0].addresses, vec![0x1000, 0x1001, 0x1006]);
        assert_eq!(pseudocode.lines[2].addresses, vec![0x1004, 0x1007]);
        assert_eq!(
            pseudocode
                .line_addresses()
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![0, 2],
            "the braces come from no instruction"
        );
    }

    // ---- the options -------------------------------------------------------

    #[test]
    fn the_parameters_option_declares_every_register_of_the_convention() {
        // mov eax, edi; ret
        let code = [0x89, 0xf8, 0xc3];
        assert_eq!(c(&code), "int f(int a)\n{\n  return a;\n}");
        assert_eq!(
            c_with(&code, &names, &[("parameters", "convention")]),
            "int f(int a, long b, long c, long d, long e, long f)\n{\n  return a;\n}"
        );
    }

    #[test]
    fn the_merged_register_names_option_numbers_the_variables() {
        // cmp edi, 0; jle .else; mov eax, 1; jmp .join; .else: mov eax, 2; .join: ret
        let code = [
            0x83, 0xff, 0x00, 0x7e, 0x07, 0xb8, 1, 0, 0, 0, 0xeb, 0x05, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        assert!(c(&code).contains("  int eax;\n"), "{}", c(&code));
        let numbered = c_with(&code, &names, &[("merged-register-names", "numbered")]);
        assert_eq!(
            numbered,
            "int f(int a)\n\
             {\n\
             \x20 int var_1;\n\
             \n\
             \x20 if (a <= 0) {\n\
             \x20   var_1 = 2;\n\
             \x20 } else {\n\
             \x20   var_1 = 1;\n\
             \x20 }\n\
             \x20 return var_1;\n\
             }"
        );

        // xor eax, eax; .top: add eax, edi; sub edi, 1; jne .top; ret: two
        // registers become variables, numbered in turn.
        let code = [0x31, 0xc0, 0x01, 0xf8, 0x83, 0xef, 0x01, 0x75, 0xf9, 0xc3];
        let numbered = c_with(&code, &names, &[("merged-register-names", "numbered")]);
        assert!(
            numbered.contains("  int var_1;\n  int var_2;\n"),
            "{numbered}"
        );
        assert!(numbered.contains("} while (var_2 != 0);"), "{numbered}");
    }

    #[test]
    fn the_stack_slot_names_option_spells_the_offset_in_decimal() {
        // mov [rsp-0x14], edi; lea rax, [rsp-0x14]; ret: the slot's address
        // is taken, so it is a declared local.
        let code = [0x89, 0x7c, 0x24, 0xec, 0x48, 0x8d, 0x44, 0x24, 0xec, 0xc3];
        assert_eq!(
            c(&code),
            "long f(int a)\n{\n  int local_14;\n\n  local_14 = a;\n  return &local_14;\n}"
        );
        assert_eq!(
            c_with(&code, &names, &[("stack-slot-names", "decimal")]),
            "long f(int a)\n{\n  int local_20;\n\n  local_20 = a;\n  return &local_20;\n}"
        );
    }

    #[test]
    fn the_pointer_loads_option_prints_named_data_as_a_cast() {
        // mov eax, [rip+0x2001]; ret: loads 0x3007, the data `counter`.
        let code = [0x8b, 0x05, 0x01, 0x20, 0x00, 0x00, 0xc3];
        assert_eq!(c_with_image(&code), "int f(void)\n{\n  return counter;\n}");
        assert_eq!(
            c_with(&code, &Image, &[("pointer-loads", "cast")]),
            "int f(void)\n{\n  return *(int *)0x3007;\n}"
        );
        // The pointer taken through lea is still the name: the option is
        // about loads and stores.
        assert_eq!(
            c_with(
                &[0x48, 0x8d, 0x05, 0x00, 0x20, 0x00, 0x00, 0xc3],
                &Image,
                &[("pointer-loads", "cast")]
            ),
            "long f(void)\n{\n  return &counter;\n}"
        );
    }

    #[test]
    fn the_operand_order_option_sorts_the_operands_of_a_commutative_operator() {
        // mov eax, esi; add eax, edi; ret: the add names b first.
        let code = [0x89, 0xf0, 0x01, 0xf8, 0xc3];
        assert_eq!(c(&code), "int f(int a, int b)\n{\n  return b + a;\n}");
        assert_eq!(
            c_with(&code, &names, &[("operand-order", "canonical")]),
            "int f(int a, int b)\n{\n  return a + b;\n}"
        );
        // mov eax, 3; add eax, edi; ret: the constant goes last, and a
        // subtraction keeps its order.
        assert_eq!(
            c_with(
                &[0xb8, 3, 0, 0, 0, 0x01, 0xf8, 0xc3],
                &names,
                &[("operand-order", "canonical")]
            ),
            "int f(int a)\n{\n  return a + 3;\n}"
        );
        assert_eq!(
            c_with(
                &[0x89, 0xf0, 0x29, 0xf8, 0xc3],
                &names,
                &[("operand-order", "canonical")]
            ),
            "int f(int a, int b)\n{\n  return b - a;\n}"
        );
    }

    #[test]
    fn the_unsigned_compare_option_drops_the_casts() {
        // cmp edi, esi; jb .else; mov eax, 1; jmp .join; .else: mov eax, 2; .join: ret
        let code = [
            0x39, 0xf7, 0x72, 0x07, 0xb8, 1, 0, 0, 0, 0xeb, 0x05, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        assert!(
            c(&code).contains("if ((unsigned int)a < (unsigned int)b) {"),
            "{}",
            c(&code)
        );
        let bare = c_with(&code, &names, &[("unsigned-compare", "bare")]);
        assert!(bare.contains("if (a < b) {"), "{bare}");
        assert!(!bare.contains("unsigned"), "{bare}");
    }

    #[test]
    fn the_dead_compares_option_keeps_a_compare_no_branch_reads() {
        // mov eax, edi; cmp eax, esi; test eax, eax; ret: nothing reads
        // either's flags.
        let code = [0x89, 0xf8, 0x39, 0xf0, 0x85, 0xc0, 0xc3];
        assert_eq!(c(&code), "int f(int a, int b)\n{\n  return a;\n}");
        assert_eq!(
            c_with(&code, &names, &[("dead-compares", "keep")]),
            "int f(int a, int b)\n{\n  __cmp(a, b);\n  __test(a, a);\n  return a;\n}"
        );
        // cmp edi, 0; jle .else; mov eax, 1; jmp .join; .else: mov eax, 2;
        // .join: ret: the branch reads the compare, so nothing is kept.
        let code = [
            0x83, 0xff, 0x00, 0x7e, 0x07, 0xb8, 1, 0, 0, 0, 0xeb, 0x05, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        assert_eq!(
            c_with(&code, &names, &[("dead-compares", "keep")]),
            c(&code)
        );
    }
}
