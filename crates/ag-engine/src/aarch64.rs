//! AArch64 — lifted to pseudocode through the architecture seam.
//!
//! The decode is the ARM decoder's: the same SLEIGH runtime reading the
//! AArch64 specification (see [`crate::arm`]). What this module adds is the
//! lift. The engine's lifter reads x86-64 through its own decoder's
//! mnemonics and operands; AArch64 comes to it through
//! [`crate::plugin::Architecture::lift`], the seam built for an
//! architecture that lifts its own language: this one reads each
//! instruction's p-code — the same p-code the flow is read from — and
//! interprets it into the medium level, blocks of statements over
//! variables, which the engine then structures into pseudocode as it does
//! its own lift.
//!
//! # How it works
//!
//! Each instruction's p-code is a short program of copies, arithmetic,
//! loads, stores and the one operation that moves control. The lift walks
//! the function's blocks with a symbolic state:
//!
//! * **Registers hold expressions.** Each general register maps to the
//!   expression it currently holds, with the width of the last write: a
//!   `w` write (a zero-extension into the 64-bit file, which is how the
//!   specification lifts it) records width 32, and reading the whole `x`
//!   file of it is a cast. The instruction's temporaries are folded: an
//!   `add w0, w0, w0, LSL #1` arrives as a shift and an add into
//!   temporaries, and folds to `a + (a << 1)`.
//! * **Loads and stores are statements.** A load names its result by the
//!   register it lands in (`w1 = *(int *)x19;`) and a store is the typed
//!   write (`*(int *)x19 = w2;`). A post-index add to the base waits for
//!   the access it was saved before, so the increment never moves the
//!   load out from under itself.
//! * **The frame is skipped.** A store or a load through the stack
//!   pointer, and any write of `x29` or `x30` — the `stp`/`ldp` of a
//!   prologue and epilogue and the `mov` that sets the frame pointer —
//!   are the frame the signature line stands for, not statements.
//! * **Conditions come from the flag producer.** `cmp`, `subs` and their
//!   kind record what they compared, read through the state after the
//!   instruction ran; the branch's mnemonic says the relation — `b.lt`
//!   after `cmp w1, #1` is `b < 1`, `b.ne` after `subs x20, x20, #1` is
//!   `x20 != 0`, read through the assignment the subtraction already
//!   made. A branch whose flags no tracked instruction set is refused by
//!   name.
//! * **Parameters** are the AAPCS64 argument registers (`x0`–`x7`) read
//!   before they are written, named `a`, `b`, `c`… by position. **Calls**
//!   pass the argument registers written before them, leave the result in
//!   `x0`, and forget the caller-saved registers (`x0`–`x18`), as the
//!   x86-64 lifter does.
//! * **A register that differs where paths join becomes a variable**
//!   named after the register (`x19`, `x20`), assigned by the writes each
//!   path makes. The function is lifted again with those registers made
//!   variables — the loop-carried ones among them — until nothing more
//!   changes, as the x86-64 lifter re-lifts its loops.
//! * **`ret`** returns `x0` at the width of the narrowest explicit write
//!   to it on the paths that wrote it; a path that only hands on a
//!   callee's result follows the others. With nothing written anywhere,
//!   the function returns void.
//!
//! What the interpreter does not understand — a select (`csinv`), an
//! indirect branch, a vector register — refuses the function with the
//! mnemonic, the way the x86-64 lifter refuses an instruction it does not
//! read. A multiply-accumulate (`madd`) is not among them: it lowers to a
//! multiply and an add, both read, and lifts.

use std::collections::{BTreeMap, HashMap};

use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;

use crate::arch::Bitness;
use crate::arm::{self, ArmVariant, Op};
use crate::ast::{AstNode, BinaryOp};
use crate::cpu_context::Flow;
use crate::lift::{NotLifted, Statement, StatementKind, Variable};
use crate::plugin::{Architecture, DecodedSection, FunctionCode, LiftedGraph};
use crate::structure::{Node, Terminator};

/// The architecture: AArch64, decoded by the ARM decoder and lifted here.
#[derive(Debug, Clone, Copy)]
pub struct Arch;

impl Architecture for Arch {
    fn name(&self) -> &str {
        "aarch64"
    }

    fn languages(&self) -> Vec<String> {
        vec![
            "AARCH64:LE:64:v8A".to_string(),
            "AARCH64:LE:64:v8A:default".to_string(),
            "AARCH64:LE:64:AppleSilicon".to_string(),
        ]
    }

    fn bitness(&self, _language: &str) -> Bitness {
        Bitness::Bits64
    }

    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let variant = ArmVariant::of_language(language)
            .filter(|variant| !variant.has_modes())
            .ok_or_else(|| format!("{language} is not AArch64"))?;
        let decoded = arm::decode_section(variant, bytes, base, &BTreeMap::new(), &BTreeMap::new())
            .map_err(|error| format!("{error:#}"))?;
        Ok(DecodedSection {
            disasm: decoded.disasm,
            text: decoded
                .text
                .into_iter()
                .map(|(address, (mnemonic, operands))| (address, (mnemonic, operands, Vec::new())))
                .collect(),
        })
    }

    fn lifts(&self, language: &str) -> bool {
        ArmVariant::of_language(language).is_some_and(|variant| !variant.has_modes())
    }

    fn lift(&self, function: &FunctionCode) -> Option<Result<LiftedGraph, String>> {
        let variant = ArmVariant::of_language(function.language)?;
        Some(lift_function(function, variant).map_err(|error| error.reason))
    }
}

/// The register file as the specification numbers it: `x0` is offset
/// `0x4000`, eight bytes a register, `x30` the last; the stack pointer is
/// `0x8`. The program counter (`0x0`) and the condition flags
/// (`0x100`–`0x108`) name no register here.
const REG_BASE: u64 = 0x4000;
const SP: u64 = 0x8;

/// The condition flags and their intermediates, which the lift reads
/// through the flag producer rather than per operation.
const FLAGS: std::ops::RangeInclusive<u64> = 0x100..=0x108;

/// The general registers: `x0`–`x30` and the stack pointer at 31.
const GPRS: usize = 32;

/// How often a function is re-lifted to settle its variables, as the
/// x86-64 lifter re-lifts its loops.
const PASSES: usize = 8;

/// The names of the parameters, by argument position.
const PARAM_NAMES: [&str; 8] = ["a", "b", "c", "d", "e", "f", "g", "h"];

/// The register a register-space varnode names, as an index into the file
/// and the width of the slice, when it names one.
fn gpr_of(offset: u64, size: u32) -> Option<(usize, u32)> {
    if offset == SP {
        return (size <= 8).then_some((31, size.min(8) * 8));
    }
    if !(REG_BASE..=REG_BASE + 8 * 30).contains(&offset) {
        return None;
    }
    ((offset - REG_BASE).is_multiple_of(8) && size <= 8)
        .then(|| (((offset - REG_BASE) / 8) as usize, size * 8))
}

/// The space a varnode lives in, by name.
fn space_of(varnode: &VarnodeData) -> String {
    varnode
        .space
        .as_ref()
        .map(|space| space.get_name().to_string())
        .unwrap_or_default()
}

/// Whether the varnode is a condition flag or one of the specification's
/// intermediates: the lift reads the flags through the producer of them,
/// so operations that write one are passed over.
fn is_flag(varnode: &VarnodeData) -> bool {
    space_of(varnode) == "register" && FLAGS.contains(&varnode.offset)
}

/// The name of the register file `index` read `bits` wide.
fn register_name(index: usize, bits: u32) -> String {
    if index == 31 {
        return "sp".to_string();
    }
    match bits {
        8 | 16 | 32 => format!("w{index}"),
        _ => format!("x{index}"),
    }
}

/// The C type of a value `bits` wide.
fn type_of(bits: u32) -> &'static str {
    match bits {
        8 => "char",
        16 => "short",
        32 => "int",
        _ => "long",
    }
}

/// What a register or a temporary holds: the expression, the width of the
/// write that put it there, and whether it is rooted in the stack pointer
/// — a pointer into the frame.
#[derive(Debug, Clone, PartialEq)]
struct Value {
    node: AstNode,
    bits: u32,
    frame: bool,
}

impl Value {
    fn of(node: AstNode, bits: u32) -> Value {
        Value {
            node,
            bits,
            frame: false,
        }
    }
}

/// What the last flag-setting instruction compared, read through the
/// state after it ran: `a` and `b`, and the register a `subs` wrote the
/// difference to — the condition then tests that register against zero.
/// A `cmp` or `cmn` wrote its result to wzr and names no register: its
/// condition compares `a` with `b`. A `tst` recorded the and of its
/// operands against zero.
#[derive(Debug, Clone, PartialEq)]
struct Flags {
    a: AstNode,
    b: AstNode,
    dest: Option<usize>,
}

/// The state at one program point.
#[derive(Debug, Clone, PartialEq)]
struct State {
    regs: Vec<Option<Value>>,
    flags: Option<Flags>,
}

impl State {
    fn new() -> State {
        let mut regs = vec![None; GPRS];
        regs[31] = Some(Value {
            node: AstNode::var("sp"),
            bits: 64,
            frame: true,
        });
        State { regs, flags: None }
    }
}

/// The p-code, the text and the flow of one instruction.
struct Decoded {
    ops: Vec<Op>,
    mnemonic: String,
    flow: Flow,
}

/// Lift the function `function` gives, under `variant`.
fn lift_function(function: &FunctionCode, variant: ArmVariant) -> Result<LiftedGraph, NotLifted> {
    let blocks = &function.cfg.blocks;
    if blocks.is_empty() {
        return Err(NotLifted::new("no blocks"));
    }
    let entry = blocks
        .iter()
        .position(|block| block.from == function.address)
        .unwrap_or(0);
    // The p-code, the text and the flow of every instruction of the
    // function's blocks, read from the decoder one instruction at a time.
    let mut code: HashMap<u64, Decoded> = HashMap::new();
    for block in blocks {
        let mut at = block.from;
        while at < block.to {
            let Some(ins) = function.disasm.instruction_at(at) else {
                break;
            };
            let (ops, mnemonic, _) =
                arm::instruction_ops(variant, function.bytes, function.base, at)
                    .map_err(|error| NotLifted::new(format!("{error:#}")))?;
            code.insert(
                at,
                Decoded {
                    ops,
                    mnemonic,
                    flow: ins.flow,
                },
            );
            at += ins.length as u64;
        }
    }
    let index_of: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.from, index))
        .collect();

    // The registers made variables: first none, then every one that
    // differed at a join, until the set settles — the loop-carried
    // registers among them, as the x86-64 lifter re-lifts its loops.
    let mut made: BTreeMap<usize, (String, u32)> = BTreeMap::new();
    let mut params: BTreeMap<usize, (String, u32)> = BTreeMap::new();
    for _ in 0..PASSES {
        let attempt = lift_pass(function, blocks, &index_of, entry, &code, &made, &params)?;
        let mut fresh = false;
        // Parameters first: a register that is both an argument and
        // loop-carried keeps its parameter name, not its register name.
        for (index, bits, name) in &attempt.params {
            if !params.contains_key(index) {
                params.insert(*index, (name.clone(), *bits));
                fresh = true;
            }
        }
        for (index, bits, name) in &attempt.need {
            if !made.contains_key(index) && !params.contains_key(index) {
                made.insert(*index, (name.clone(), *bits));
                fresh = true;
            }
        }
        if !fresh {
            return Ok(graph(function, attempt, params, made));
        }
    }
    Err(NotLifted::new("the loop variables did not settle"))
}

/// What one walk of the blocks produced.
struct Walked {
    nodes: Vec<Node>,
    frame: Vec<u64>,
    /// The registers that differed at a join and must become variables:
    /// the file index, the width of the widest value seen, and the name.
    need: Vec<(usize, u32, String)>,
    /// The registers read before written: the file index, the width of the
    /// first read, and the name.
    params: Vec<(usize, u32, String)>,
    /// The locals the load statements name.
    locals: BTreeMap<String, u32>,
    /// The width of the narrowest explicit write to `x0` on a path that
    /// returned a value.
    returns: Option<u32>,
    /// Whether any path made a call, whose result the `x0` local holds.
    calls: bool,
}

/// One walk of the blocks in order, joining the states, with `made` and
/// `params` already made variables.
fn lift_pass(
    function: &FunctionCode,
    blocks: &[crate::cfg::BasicBlock],
    index_of: &HashMap<u64, usize>,
    entry: usize,
    code: &HashMap<u64, Decoded>,
    made: &BTreeMap<usize, (String, u32)>,
    params: &BTreeMap<usize, (String, u32)>,
) -> Result<Walked, NotLifted> {
    let mut walked = Walked {
        nodes: blocks
            .iter()
            .map(|block| Node {
                address: block.from,
                statements: Vec::new(),
                terminator: Terminator::Return,
            })
            .collect(),
        frame: Vec::new(),
        need: Vec::new(),
        params: Vec::new(),
        locals: BTreeMap::new(),
        returns: None,
        calls: false,
    };
    // The state entering each block, joined over the blocks that reach it.
    // The walk runs in address order and again until the joins stop
    // changing: a loop's header is walked with what its latch carries.
    let mut inputs: Vec<Option<State>> = vec![None; blocks.len()];
    inputs[entry] = Some(State::new());
    for _round in 0..PASSES {
        let mut changed = false;
        for index in 0..blocks.len() {
            let Some(input) = inputs[index].clone() else {
                continue;
            };
            let block = &blocks[index];
            let instructions: Vec<u64> = function
                .disasm
                .instructions
                .iter()
                .filter(|ins| ins.address >= block.from && ins.address < block.to)
                .map(|ins| ins.address)
                .collect();
            let mut run = Run {
                code,
                names: function.names,
                statements: Vec::new(),
                frame: &mut walked.frame,
                made,
                params,
                new_params: &mut walked.params,
                locals: &mut walked.locals,
                returns: &mut walked.returns,
                calls: &mut walked.calls,
                flags: input.flags,
                regs: input.regs,
            };
            let terminator = run.walk_block(&instructions, block, index_of)?;
            let output = State {
                regs: run.regs,
                flags: run.flags,
            };
            walked.nodes[index].statements = run.statements;
            walked.nodes[index].terminator = terminator;
            // The state leaves to each successor, joined with what is
            // already there: what agrees stays, what differs is made a
            // variable and carried as its name.
            for successor in &block.successor_addresses {
                let Some(&target) = index_of.get(successor) else {
                    continue;
                };
                let joined = match inputs[target].take() {
                    None => Some(output.clone()),
                    Some(before) => Some(join(&before, &output, made, params, &mut walked.need)),
                };
                if let Some(joined) = joined {
                    changed |= inputs[target].as_ref() != Some(&joined);
                    inputs[target] = Some(joined);
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(walked)
}

/// One block's walk: the p-code of its instructions, interpreted.
struct Run<'a> {
    code: &'a HashMap<u64, Decoded>,
    names: &'a BTreeMap<u64, String>,
    statements: Vec<Statement>,
    frame: &'a mut Vec<u64>,
    made: &'a BTreeMap<usize, (String, u32)>,
    params: &'a BTreeMap<usize, (String, u32)>,
    new_params: &'a mut Vec<(usize, u32, String)>,
    locals: &'a mut BTreeMap<String, u32>,
    returns: &'a mut Option<u32>,
    calls: &'a mut bool,
    flags: Option<Flags>,
    regs: Vec<Option<Value>>,
}

/// What one instruction's p-code left standing between its operations:
/// the temporaries it computed, the base a load or store reads through
/// (a post-index add to it follows the access), and the condition a
/// `cbz`-style branch built from real operands rather than flags.
#[derive(Default)]
struct Scratch {
    temps: BTreeMap<(u64, u32), Value>,
    /// The register whose value was saved into a temporary this
    /// instruction: a later add to the register is the post-index bump,
    /// assigned to the base's own name.
    saved: Option<usize>,
    /// The bump, held until the access it follows has been said.
    bump: Option<Statement>,
    condition: Option<AstNode>,
}

impl Run<'_> {
    /// The name of the variable the register `index` became, when it is
    /// one.
    fn variable(&self, index: usize) -> Option<&str> {
        self.params
            .get(&index)
            .or_else(|| self.made.get(&index))
            .map(|(name, _)| name.as_str())
    }

    /// The value of the register file `index` read `bits` wide: a variable
    /// reads as its name, an expression as itself, widened when the read
    /// is wider than the write. An argument register read before it is
    /// written is a parameter; any other register read before it is
    /// written holds its incoming value, named after itself.
    fn read(&mut self, index: usize, bits: u32, _at: u64) -> Result<Value, NotLifted> {
        if let Some(name) = self.variable(index) {
            return Ok(Value::of(AstNode::var(name), bits.min(64)));
        }
        match self.regs.get(index).and_then(Option::as_ref) {
            Some(value) => {
                let node = widen(&value.node, value.bits, bits);
                Ok(Value {
                    node,
                    bits,
                    frame: value.frame,
                })
            }
            None if index < 8 => {
                let name = PARAM_NAMES[index].to_string();
                if !self.new_params.iter().any(|(i, _, _)| *i == index) {
                    self.new_params.push((index, bits, name.clone()));
                }
                // Pin it: the register holds its incoming argument, so a
                // join of two paths that only read it agrees.
                let value = Value::of(AstNode::var(&name), bits);
                self.regs[index] = Some(value.clone());
                Ok(value)
            }
            None if index == 31 => Ok(Value {
                node: AstNode::var("sp"),
                bits: 64,
                frame: true,
            }),
            None => Ok(Value::of(AstNode::var(register_name(index, bits)), bits)),
        }
    }

    /// The value of a varnode: a register, a constant, or a temporary the
    /// instruction computed. `None` for one the lift does not track — a
    /// flag, the program counter, a vector register.
    fn operand(
        &mut self,
        varnode: &VarnodeData,
        scratch: &mut Scratch,
        at: u64,
    ) -> Result<Option<Value>, NotLifted> {
        match space_of(varnode).as_str() {
            "const" => Ok(Some(Value::of(
                AstNode::constant(varnode.offset, varnode.size),
                varnode.size * 8,
            ))),
            "unique" => Ok(scratch.temps.get(&(varnode.offset, varnode.size)).cloned()),
            "register" => match gpr_of(varnode.offset, varnode.size) {
                Some((index, bits)) => self.read(index, bits, at).map(Some),
                None => Ok(None),
            },
            _ => Ok(None),
        }
    }

    /// The write of a value into the register file `index`: a variable is
    /// assigned with a statement, an expression is kept in the state.
    fn write(&mut self, index: usize, value: Value, at: u64) {
        if let Some(name) = self.variable(index).map(str::to_string) {
            let bits = value.bits;
            self.statements.push(Statement {
                node: AstNode::Assign {
                    lhs: Box::new(AstNode::var(&name)),
                    rhs: Box::new(value.node),
                },
                addresses: vec![at],
                kind: StatementKind::Plain,
            });
            self.regs[index] = Some(Value::of(AstNode::var(name), bits));
        } else {
            self.regs[index] = Some(value);
        }
    }

    /// Whether the instruction is a frame move: it loads or stores, and
    /// every pointer it reads through is the stack pointer or a temporary
    /// grown from it — the `stp`/`ldp` of a prologue and epilogue.
    fn is_frame(ops: &[Op]) -> bool {
        let mut frame_temps: BTreeMap<(u64, u32), bool> = BTreeMap::new();
        let mut accesses = 0;
        let mut framed = 0;
        for op in ops {
            match op.opcode {
                OpCode::CPUI_COPY | OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB => {
                    let Some(out) = &op.out else { continue };
                    if space_of(out) != "unique" {
                        continue;
                    }
                    // A temporary is rooted in the frame when the value
                    // it copies, or the base it adds to, is the stack
                    // pointer or another frame temporary.
                    let rooted = op.inputs.first().is_some_and(|input| {
                        (space_of(input) == "register" && input.offset == SP)
                            || (space_of(input) == "unique"
                                && frame_temps
                                    .get(&(input.offset, input.size))
                                    .copied()
                                    .unwrap_or(false))
                    });
                    frame_temps.insert((out.offset, out.size), rooted);
                }
                OpCode::CPUI_LOAD | OpCode::CPUI_STORE => {
                    accesses += 1;
                    let Some(pointer) = op.inputs.get(1) else {
                        continue;
                    };
                    let rooted = space_of(pointer) == "register" && pointer.offset == SP
                        || space_of(pointer) == "unique"
                            && frame_temps
                                .get(&(pointer.offset, pointer.size))
                                .copied()
                                .unwrap_or(false);
                    if rooted {
                        framed += 1;
                    }
                }
                _ => {}
            }
        }
        accesses > 0 && framed == accesses
    }

    /// Interpret one instruction's p-code, appending its statements.
    fn run_instruction(
        &mut self,
        at: u64,
        mnemonic: &str,
        ops: &[Op],
        scratch: &mut Scratch,
    ) -> Result<(), NotLifted> {
        let frame = Self::is_frame(ops);
        // The load's statement, held until the instruction ends: a
        // post-index bump of its base must follow it, not precede it.
        let mut load: Option<Statement> = None;
        // What the flag producer compared, captured as its subtraction
        // runs: the operands, and the register the result lands in.
        let mut produced: Option<Flags> = None;
        let flags_producer = matches!(mnemonic, "cmp" | "subs" | "cmn" | "adds" | "tst" | "sbcs");
        for op in ops {
            // A flag or an intermediate written by the producer: read
            // through the record, not per operation.
            if op.out.as_ref().is_some_and(is_flag) {
                continue;
            }
            match op.opcode {
                OpCode::CPUI_COPY | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(source) = self.operand(&op.inputs[0], scratch, at)? else {
                        // A copy of a flag, or of the link register into
                        // the program counter: tracked nowhere, and the
                        // flow was read from the p-code already.
                        if space_of(out) != "unique" {
                            continue;
                        }
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let mut value = source;
                    if matches!(op.opcode, OpCode::CPUI_INT_SEXT) {
                        value.node = AstNode::Cast {
                            ty: "long".to_string(),
                            target: Box::new(value.node),
                        };
                    }
                    // A zero-extension into the 64-bit file keeps the
                    // width of what it extended: a `w` write is 32 bits.
                    if !matches!(op.opcode, OpCode::CPUI_INT_ZEXT) {
                        value.bits = out.size * 8;
                    }
                    match (space_of(out).as_str(), gpr_of(out.offset, out.size)) {
                        ("register", Some((31, _))) => {
                            self.regs[31] = Some(Value {
                                node: value.node,
                                bits: 64,
                                frame: true,
                            });
                        }
                        ("register", Some((index, _))) => {
                            if frame || index == 29 || index == 30 {
                                continue;
                            }
                            self.write(index, value, at);
                        }
                        ("unique", _) => {
                            let rooted = op.inputs.first().is_some_and(|input| {
                                space_of(input) == "register" && input.offset == SP
                                    || space_of(input) == "unique"
                                        && scratch
                                            .temps
                                            .get(&(input.offset, input.size))
                                            .is_some_and(|value| value.frame)
                            });
                            value.frame = value.frame || rooted;
                            if rooted {
                                value.node = AstNode::var("sp");
                            }
                            // The base a load or store will read through:
                            // a later add to the register is the bump.
                            if let Some(input) = op.inputs.first() {
                                if space_of(input) == "register" {
                                    if let Some((index, _)) = gpr_of(input.offset, input.size) {
                                        scratch.saved = Some(index);
                                    }
                                }
                            }
                            scratch.temps.insert((out.offset, out.size), value);
                        }
                        _ => {}
                    }
                }
                OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch, at)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(b) = self.operand(&op.inputs[1], scratch, at)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    if flags_producer && space_of(out) == "unique" {
                        produced = Some(Flags {
                            a: a.node.clone(),
                            b: b.node.clone(),
                            dest: None,
                        });
                    }
                    let node = AstNode::binary(
                        a.node,
                        if matches!(op.opcode, OpCode::CPUI_INT_ADD) {
                            BinaryOp::Add
                        } else {
                            BinaryOp::Sub
                        },
                        b.node,
                    );
                    let value = Value {
                        node,
                        bits: out.size * 8,
                        frame: a.frame || b.frame,
                    };
                    match (space_of(out).as_str(), gpr_of(out.offset, out.size)) {
                        ("register", Some((31, _))) => {
                            self.regs[31] = Some(Value {
                                node: value.node,
                                bits: 64,
                                frame: true,
                            });
                        }
                        ("register", Some((index, _))) => {
                            if frame || index == 29 || index == 30 {
                                continue;
                            }
                            // The post-index bump of a saved base: the
                            // access was said from the saved value, so
                            // the bump is the base's own assignment, and
                            // waits for the access to be said first.
                            if scratch.saved == Some(index) {
                                let base = self.base_node(index);
                                scratch.bump = Some(Statement {
                                    node: AstNode::Assign {
                                        lhs: Box::new(base.clone()),
                                        rhs: Box::new(value.node),
                                    },
                                    addresses: vec![at],
                                    kind: StatementKind::Plain,
                                });
                                self.regs[index] = Some(Value::of(base, value.bits));
                                scratch.saved = None;
                            } else {
                                self.write(index, value, at);
                            }
                        }
                        ("unique", _) => {
                            scratch.temps.insert((out.offset, out.size), value);
                        }
                        _ => {}
                    }
                }
                OpCode::CPUI_LOAD => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(pointer) = self.operand(&op.inputs[1], scratch, at)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let deref = AstNode::Deref {
                        target: Box::new(AstNode::Cast {
                            ty: format!("{} *", type_of(out.size * 8)),
                            target: Box::new(pointer.node),
                        }),
                    };
                    match gpr_of(out.offset, out.size) {
                        Some((index, bits)) => {
                            if frame {
                                continue;
                            }
                            let name = match self.variable(index) {
                                Some(name) => format!("{name}_loaded"),
                                None => register_name(index, bits),
                            };
                            self.locals
                                .entry(name.clone())
                                .and_modify(|wide| *wide = (*wide).max(bits))
                                .or_insert(bits);
                            load = Some(Statement {
                                node: AstNode::Assign {
                                    lhs: Box::new(AstNode::var(&name)),
                                    rhs: Box::new(deref),
                                },
                                addresses: vec![at],
                                kind: StatementKind::Plain,
                            });
                            self.regs[index] = Some(Value::of(AstNode::var(name), bits));
                        }
                        None => {
                            scratch
                                .temps
                                .insert((out.offset, out.size), Value::of(deref, out.size * 8));
                        }
                    }
                }
                OpCode::CPUI_STORE => {
                    let Some(pointer) = self.operand(&op.inputs[1], scratch, at)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(value) = self.operand(&op.inputs[2], scratch, at)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let width = value.bits;
                    if !frame {
                        self.statements.push(Statement {
                            node: AstNode::Assign {
                                lhs: Box::new(AstNode::Deref {
                                    target: Box::new(AstNode::Cast {
                                        ty: format!("{} *", type_of(width)),
                                        target: Box::new(pointer.node),
                                    }),
                                }),
                                rhs: Box::new(value.node),
                            },
                            addresses: vec![at],
                            kind: StatementKind::Plain,
                        });
                    }
                }
                OpCode::CPUI_INT_LEFT
                | OpCode::CPUI_INT_RIGHT
                | OpCode::CPUI_INT_SRIGHT
                | OpCode::CPUI_INT_AND
                | OpCode::CPUI_INT_OR
                | OpCode::CPUI_INT_XOR
                | OpCode::CPUI_INT_MULT => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch, at)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(b) = self.operand(&op.inputs[1], scratch, at)? else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let node = AstNode::binary(
                        a.node,
                        match op.opcode {
                            OpCode::CPUI_INT_LEFT => BinaryOp::Shl,
                            OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => BinaryOp::Shr,
                            OpCode::CPUI_INT_AND => BinaryOp::And,
                            OpCode::CPUI_INT_OR => BinaryOp::Or,
                            OpCode::CPUI_INT_XOR => BinaryOp::Xor,
                            _ => BinaryOp::Mul,
                        },
                        b.node,
                    );
                    // A `tst` is an and that sets the flags: the record
                    // says what it masked, tested against zero, as the
                    // add and sub handlers record what a `cmp` compared.
                    if flags_producer
                        && mnemonic == "tst"
                        && matches!(op.opcode, OpCode::CPUI_INT_AND)
                        && space_of(out) == "unique"
                    {
                        produced = Some(Flags {
                            a: node.clone(),
                            b: AstNode::constant(0, out.size),
                            dest: None,
                        });
                    }
                    let value = Value {
                        node,
                        bits: out.size * 8,
                        frame: a.frame,
                    };
                    match (space_of(out).as_str(), gpr_of(out.offset, out.size)) {
                        ("register", Some((index, _))) if !frame && index != 29 && index != 30 => {
                            self.write(index, value, at)
                        }
                        ("register", Some((31, _))) => {
                            self.regs[31] = Some(Value {
                                node: value.node,
                                bits: 64,
                                frame: true,
                            });
                        }
                        ("unique", _) => {
                            scratch.temps.insert((out.offset, out.size), value);
                        }
                        _ => {}
                    }
                }
                OpCode::CPUI_BOOL_NEGATE => {
                    // The negation of a flag, feeding a branch's test:
                    // the condition is read from the producer's record
                    // and the mnemonic, so a negation of a flag operand
                    // needs no temporary.
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch, at)? else {
                        continue;
                    };
                    let node = AstNode::Cast {
                        ty: "!".to_string(),
                        target: Box::new(a.node),
                    };
                    scratch
                        .temps
                        .insert((out.offset, out.size), Value::of(node, out.size * 8));
                }
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                    let Some(out) = &op.out else {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    };
                    let Some(a) = self.operand(&op.inputs[0], scratch, at)? else {
                        continue;
                    };
                    let Some(b) = self.operand(&op.inputs[1], scratch, at)? else {
                        continue;
                    };
                    let node = AstNode::binary(
                        a.node,
                        if matches!(op.opcode, OpCode::CPUI_INT_EQUAL) {
                            BinaryOp::Equal
                        } else {
                            BinaryOp::NotEqual
                        },
                        b.node,
                    );
                    scratch
                        .temps
                        .insert((out.offset, out.size), Value::of(node, out.size * 8));
                }
                OpCode::CPUI_CBRANCH => {
                    // A branch to a constant is a select's internal
                    // jump (`csinv`): the lift does not read it.
                    if op
                        .inputs
                        .first()
                        .is_some_and(|target| space_of(target) == "const")
                    {
                        return Err(NotLifted::new(mnemonic.to_string()));
                    }
                    if let Some(condition) = op.inputs.get(1).cloned() {
                        scratch.condition = self
                            .operand(&condition, scratch, at)?
                            .map(|value| value.node);
                    }
                }
                OpCode::CPUI_BRANCH
                | OpCode::CPUI_CALL
                | OpCode::CPUI_CALLIND
                | OpCode::CPUI_RETURN => {}
                _ => return Err(NotLifted::new(mnemonic.to_string())),
            }
        }
        // The access statements, in the order the machine runs them:
        // the load first, then the bump that moved its base.
        if let Some(statement) = load {
            self.statements.push(statement);
        }
        if let Some(bump) = scratch.bump.take() {
            self.statements.push(bump);
        }
        if let Some(mut flags) = produced {
            // A `subs` tests the register it wrote, not the operands.
            if let Some(op) = ops.iter().find(|op| {
                matches!(op.opcode, OpCode::CPUI_COPY)
                    && op.out.as_ref().is_some_and(|out| {
                        space_of(out) == "register" && gpr_of(out.offset, out.size).is_some()
                    })
            }) {
                let out = op.out.as_ref().expect("checked");
                if let Some((index, _)) = gpr_of(out.offset, out.size) {
                    flags.dest = Some(index);
                }
            }
            self.flags = Some(flags);
        }
        Ok(())
    }

    /// The node the register `index` stands by when it is bumped: its own
    /// name when it is a variable, its expression otherwise.
    fn base_node(&self, index: usize) -> AstNode {
        match self.variable(index) {
            Some(name) => AstNode::var(name),
            None => AstNode::var(register_name(index, 64)),
        }
    }

    /// Walk the instructions of one block and say how it leaves.
    fn walk_block(
        &mut self,
        instructions: &[u64],
        block: &crate::cfg::BasicBlock,
        index_of: &HashMap<u64, usize>,
    ) -> Result<Terminator, NotLifted> {
        for &at in instructions {
            let decoded = self
                .code
                .get(&at)
                .ok_or_else(|| NotLifted::new(format!("no p-code at {at:#x}")))?;
            let mnemonic = decoded.mnemonic.clone();
            let before = self.statements.len();
            let mut scratch = Scratch::default();
            self.run_instruction(at, &mnemonic, &decoded.ops, &mut scratch)?;
            match decoded.flow {
                Flow::Next => {
                    // An instruction that said nothing is the frame or a
                    // no-op: the signature line stands for it.
                    if self.statements.len() == before {
                        self.frame.push(at);
                    }
                }
                Flow::Call(target) => self.emit_call(at, target)?,
                Flow::Return => {
                    self.emit_return(at)?;
                    return Ok(Terminator::Return);
                }
                Flow::ConditionalBranch(target) => {
                    let word = mnemonic.split_whitespace().next().unwrap_or("");
                    let cond = self.condition(word, scratch.condition, at)?;
                    let taken = index_of
                        .get(&target)
                        .copied()
                        .ok_or_else(|| NotLifted::new("a branch outside the function"))?;
                    let next = block
                        .successor_addresses
                        .iter()
                        .find(|&&successor| successor != target)
                        .and_then(|successor| index_of.get(successor).copied())
                        .ok_or_else(|| NotLifted::new("a branch with no fall-through"))?;
                    return Ok(Terminator::Branch {
                        cond,
                        taken,
                        next,
                        addresses: vec![at],
                    });
                }
                Flow::UnconditionalBranch(target) => {
                    let target = index_of
                        .get(&target)
                        .copied()
                        .ok_or_else(|| NotLifted::new("a jump outside the function"))?;
                    return Ok(Terminator::Goto {
                        target,
                        addresses: vec![at],
                    });
                }
                _ => return Err(NotLifted::new(mnemonic)),
            }
        }
        // A block that runs off its end falls through to the block the
        // walk says follows it, when that block is in the function.
        match block
            .successor_addresses
            .first()
            .and_then(|successor| index_of.get(successor))
        {
            Some(&target) => Ok(Terminator::Goto {
                target,
                addresses: Vec::new(),
            }),
            None => Ok(Terminator::Return),
        }
    }

    /// The condition a branch tests: its own when it folded one (`cbz`),
    /// otherwise what the last flag producer compared, read through the
    /// state after it ran.
    fn condition(
        &mut self,
        word: &str,
        folded: Option<AstNode>,
        at: u64,
    ) -> Result<AstNode, NotLifted> {
        if let Some(cond) = folded {
            return Ok(cond);
        }
        let Some(flags) = self.flags.clone() else {
            return Err(NotLifted::new(format!(
                "{word} at {at:#x} tests flags nothing set"
            )));
        };
        let relation = match word {
            "b.eq" | "b.ne" => {
                let relation = if word == "b.eq" {
                    BinaryOp::Equal
                } else {
                    BinaryOp::NotEqual
                };
                return Ok(match flags.dest {
                    // A `subs` tests the register it wrote the
                    // difference to, not the operands.
                    Some(index) => {
                        let bits = self.regs[index].as_ref().map_or(64, |value| value.bits);
                        let value = self.read(index, bits, at)?.node;
                        let width = (bits / 8).max(1);
                        AstNode::binary(value, relation, AstNode::constant(0, width))
                    }
                    // A `cmp` or `cmn` wrote its result to wzr and named
                    // no register: the condition compares the operands
                    // the record kept.
                    None => AstNode::binary(flags.a, relation, flags.b),
                });
            }
            "b.lt" => BinaryOp::Less,
            "b.ge" => BinaryOp::GreaterEqual,
            "b.lo" | "b.cc" => BinaryOp::Less,
            "b.hs" | "b.cs" => BinaryOp::GreaterEqual,
            _ => {
                return Err(NotLifted::new(format!(
                    "{word} at {at:#x} tests flags the lift does not read"
                )))
            }
        };
        Ok(AstNode::binary(flags.a, relation, flags.b))
    }

    /// The call at `at` to `target`: the argument registers it passes, the
    /// result left in `x0`, the caller-saved registers forgotten.
    fn emit_call(&mut self, at: u64, target: u64) -> Result<(), NotLifted> {
        let args: Vec<AstNode> = (0..8)
            .filter_map(|index| self.regs[index].clone())
            .map(|value| value.node)
            .collect();
        let lhs = match self.variable(0) {
            Some(name) => name.to_string(),
            None => "x0".to_string(),
        };
        self.statements.push(Statement {
            node: AstNode::Assign {
                lhs: Box::new(AstNode::var(&lhs)),
                rhs: Box::new(AstNode::Call {
                    callee: Box::new(AstNode::FunctionName {
                        name: self
                            .names
                            .get(&target)
                            .cloned()
                            .unwrap_or_else(|| format!("sub_{target:x}")),
                        address: target,
                    }),
                    args,
                }),
            },
            addresses: vec![at],
            kind: StatementKind::Plain,
        });
        // The result stands in `x0`; the rest of the caller-saved file is
        // gone, the callee-saved registers and the frame remain. The
        // flags go with them: what the callee compared is not ours.
        self.regs[0] = Some(Value::of(AstNode::var(&lhs), 64));
        for index in 1..19 {
            self.regs[index] = None;
        }
        self.flags = None;
        *self.calls = true;
        Ok(())
    }

    /// The `ret` at `at`: the value `x0` holds, at the width the function
    /// writes it. A function that never touched `x0` returns void.
    fn emit_return(&mut self, at: u64) -> Result<(), NotLifted> {
        if self.regs[0].is_none() {
            self.statements.push(Statement {
                node: AstNode::Return { value: None },
                addresses: vec![at],
                kind: StatementKind::Plain,
            });
            return Ok(());
        }
        let bits = self.regs[0].as_ref().map_or(64, |value| value.bits);
        let value = self.read(0, bits, at)?.node;
        *self.returns = Some(match *self.returns {
            None => bits,
            Some(narrowest) => narrowest.min(bits),
        });
        self.statements.push(Statement {
            node: AstNode::Return {
                value: Some(Box::new(value)),
            },
            addresses: vec![at],
            kind: StatementKind::Plain,
        });
        Ok(())
    }
}

/// `node`, a value `from` bits wide, read as `to` bits: a wider read of a
/// narrower write is an extension.
fn widen(node: &AstNode, from: u32, to: u32) -> AstNode {
    if to <= from {
        return node.clone();
    }
    AstNode::Cast {
        ty: format!("unsigned {}", type_of(to)),
        target: Box::new(node.clone()),
    }
}

/// The join of two states at a block two paths reach: what agrees stays;
/// what differs is made a variable and carried as its name — the writes
/// each path makes assign it, so nothing is assigned here.
fn join(
    before: &State,
    coming: &State,
    made: &BTreeMap<usize, (String, u32)>,
    params: &BTreeMap<usize, (String, u32)>,
    need: &mut Vec<(usize, u32, String)>,
) -> State {
    let mut joined = coming.clone();
    for index in 0..GPRS {
        if index == 31 {
            continue;
        }
        let bits = std::cmp::max(
            before.regs[index].as_ref().map_or(0, |value| value.bits),
            coming.regs[index].as_ref().map_or(0, |value| value.bits),
        );
        let bits = if bits == 0 { 64 } else { bits };
        match (&before.regs[index], &coming.regs[index]) {
            (Some(a), Some(b)) if a.node == b.node => {}
            (None, None) => {}
            _ => {
                let name = params
                    .get(&index)
                    .or_else(|| made.get(&index))
                    .map(|(name, _)| name.clone())
                    .unwrap_or_else(|| register_name(index, bits));
                if !need.iter().any(|(i, _, _)| *i == index) {
                    need.push((index, bits, name.clone()));
                }
                joined.regs[index] = Some(Value::of(AstNode::var(&name), bits));
            }
        }
    }
    joined.flags = coming.flags.clone();
    joined
}

/// The graph the walk built: the function's signature line and its nodes.
fn graph(
    function: &FunctionCode,
    walked: Walked,
    params: BTreeMap<usize, (String, u32)>,
    made: BTreeMap<usize, (String, u32)>,
) -> LiftedGraph {
    let x0_is_param = params.contains_key(&0);
    let params: Vec<Variable> = params
        .iter()
        .map(|(_, (name, bits))| Variable::new(type_of(*bits), name.clone()))
        .collect();
    // The locals: the names the loads gave their results, and the
    // registers the joins made variables.
    let mut locals: Vec<Variable> = walked
        .locals
        .iter()
        .map(|(name, bits)| Variable::new(type_of(*bits), name.clone()))
        .collect();
    for (name, bits) in made.values() {
        if !locals.iter().any(|held| held.name == *name)
            && !params.iter().any(|held| held.name == *name)
        {
            locals.push(Variable::new(type_of(*bits), name.clone()));
        }
    }
    // The name a call left its result in, when `x0` was no variable.
    if walked.calls && !x0_is_param && !made.contains_key(&0) {
        locals.push(Variable::new("long", "x0"));
    }
    let return_type = match walked.returns {
        Some(bits) => type_of(bits).to_string(),
        None => "void".to_string(),
    };
    LiftedGraph {
        return_type,
        params,
        locals,
        entry: walked
            .nodes
            .iter()
            .position(|node| node.address == function.address)
            .unwrap_or(0),
        nodes: walked.nodes,
        frame: walked.frame,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ProcedureCfg;
    use crate::cfgwalk::resolve_branches;
    use crate::image::Image;
    use std::path::Path;

    fn fixture(name: &str) -> Image {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-image/tests/fixtures")
            .join(name);
        Image::open(&path).expect("the AArch64 fixture loads")
    }

    /// The text section of the fixture, decoded, with the graph of the
    /// function `name` walked from its symbol.
    fn function(
        image: &Image,
        name: &str,
    ) -> (Vec<u8>, u64, crate::pipeline::Disasm, ProcedureCfg, u64) {
        let variant = ArmVariant::of_language(&image.language()).expect("AArch64");
        let text = image
            .sections()
            .into_iter()
            .find(|section| section.name == ".text")
            .expect(".text");
        let bytes = image.bytes_from(text.vma).expect("bytes").to_vec();
        let decoded = arm::decode_section(
            variant,
            &bytes,
            text.vma,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .expect("decodes");
        let address = image
            .function_symbols()
            .into_iter()
            .find(|(_, found)| found == name)
            .map(|(address, _)| address)
            .unwrap_or_else(|| panic!("{name} is a symbol"));
        let cfg = resolve_branches(&decoded.disasm, address);
        (bytes, text.vma, decoded.disasm, cfg, address)
    }

    fn lift(name: &str) -> LiftedGraph {
        let image = fixture("arm64.elf");
        let (bytes, base, disasm, cfg, address) = function(&image, name);
        let language = image.language();
        let code = FunctionCode {
            language: &language,
            address,
            name,
            disasm: &disasm,
            cfg: &cfg,
            bytes: &bytes,
            base,
            names: &BTreeMap::new(),
        };
        match Arch.lift(&code) {
            Some(Ok(graph)) => graph,
            Some(Err(reason)) => panic!("{name} refused: {reason}"),
            None => panic!("{name} not lifted"),
        }
    }

    #[test]
    fn a_straight_line_function_lifts_to_a_signature_and_a_return() {
        let graph = lift("add");
        assert_eq!(graph.return_type, "int", "{:?}", graph.params);
        let names: Vec<&str> = graph
            .params
            .iter()
            .map(|param| param.name.as_str())
            .collect();
        assert_eq!(names, ["a", "b"]);
        let text = graph
            .nodes
            .iter()
            .flat_map(|node| node.statements.iter())
            .map(|statement| crate::emit::emit_node(&statement.node))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("a = b + a"), "{text}");
        assert!(text.contains("return a"), "{text}");
    }

    /// The structured pseudocode of `name`, as the engine would print it.
    fn pseudocode_of(name: &str) -> String {
        let image = fixture("arm64.elf");
        let (bytes, base, disasm, cfg, address) = function(&image, name);
        let language = image.language();
        let code = FunctionCode {
            language: &language,
            address,
            name,
            disasm: &disasm,
            cfg: &cfg,
            bytes: &bytes,
            base,
            names: &BTreeMap::new(),
        };
        let graph = match Arch.lift(&code) {
            Some(Ok(graph)) => graph,
            Some(Err(reason)) => panic!("{name} refused: {reason}"),
            None => panic!("{name} not lifted"),
        };
        let stages = crate::lift::lift_graph(
            graph,
            &disasm,
            &cfg,
            address,
            name,
            &crate::options::Options::default(),
        )
        .unwrap_or_else(|error| panic!("{name} not structured: {}", error.reason));
        crate::emit::emit_function(&stages.function, &crate::options::Options::default()).text()
    }

    #[test]
    fn a_function_structures_to_pseudocode() {
        let text = pseudocode_of("add");
        assert!(text.contains("int add("), "{text}");
        // What the lift of `sum` really says: the do-while the loop
        // structures to, the call with its arguments, the load through
        // the walking pointer, and the loop-carried registers declared
        // as locals.
        let sum = pseudocode_of("sum");
        assert!(sum.contains("while (x20 != 0)"), "{sum}");
        assert!(sum.contains("a = sub_20000(a, b);"), "{sum}");
        assert!(sum.contains("b = *(int *)x19;"), "{sum}");
        assert!(sum.contains("long x19;"), "{sum}");
        assert!(sum.contains("long x20;"), "{sum}");
    }

    #[test]
    fn a_loop_with_a_call_lifts_to_a_while_with_the_call() {
        let graph = lift("sum");
        let text = graph
            .nodes
            .iter()
            .flat_map(|node| {
                node.statements
                    .iter()
                    .map(|statement| crate::emit::emit_node(&statement.node))
                    .chain(std::iter::once(match &node.terminator {
                        Terminator::Branch { cond, .. } => {
                            format!("if ({})", crate::emit::emit_node(cond))
                        }
                        other => format!("{other:?}"),
                    }))
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("sub_20000"), "{text}");
        assert!(text.contains("if ("), "{text}");
    }

    /// A varnode in a named space, for feeding the interpreter by hand.
    fn varnode(
        space: kuna_base::space::spacetype,
        name: &str,
        offset: u64,
        size: u32,
    ) -> VarnodeData {
        VarnodeData {
            space: Some(std::rc::Rc::new(kuna_base::space::AddrSpace::new(
                space, name, false, 8, 1, 0, 0, 0, 0,
            ))),
            offset,
            size,
        }
    }

    /// Run `f` over a fresh interpreter state carrying `flags`: enough
    /// machinery for the condition and the flag record to be read, with
    /// no blocks under it.
    fn with_run<T>(flags: Option<Flags>, f: impl FnOnce(&mut Run) -> T) -> T {
        let code: HashMap<u64, Decoded> = HashMap::new();
        let names = BTreeMap::new();
        let mut frame = Vec::new();
        let made = BTreeMap::new();
        let params = BTreeMap::new();
        let mut new_params = Vec::new();
        let mut locals = BTreeMap::new();
        let mut returns: Option<u32> = None;
        let mut calls = false;
        let mut run = Run {
            code: &code,
            names: &names,
            statements: Vec::new(),
            frame: &mut frame,
            made: &made,
            params: &params,
            new_params: &mut new_params,
            locals: &mut locals,
            returns: &mut returns,
            calls: &mut calls,
            flags,
            regs: vec![None; GPRS],
        };
        f(&mut run)
    }

    /// The condition `word` reads from `flags`, as the emitter prints it.
    fn condition_text(word: &str, flags: Flags) -> String {
        with_run(Some(flags), |run| {
            let cond = run
                .condition(word, None, 0x20000)
                .unwrap_or_else(|error| panic!("{word} refused: {}", error.reason));
            crate::emit::emit_node(&cond).trim().to_string()
        })
    }

    #[test]
    fn b_cc_after_a_compare_tests_unsigned_lower() {
        // Carry-clear is `b.lo` under its other name: the same `<`.
        let flags = Flags {
            a: AstNode::var("a"),
            b: AstNode::constant(1, 4),
            dest: None,
        };
        assert_eq!(condition_text("b.cc", flags.clone()), "a < 1;");
        assert_eq!(condition_text("b.lo", flags), "a < 1;");
    }

    #[test]
    fn b_eq_and_b_ne_after_a_cmp_compare_the_operands_the_cmp_compared() {
        // A `cmp` wrote its result to wzr and named no register: the
        // condition falls back to the operands the record kept.
        let flags = Flags {
            a: AstNode::var("a"),
            b: AstNode::var("b"),
            dest: None,
        };
        assert_eq!(condition_text("b.eq", flags.clone()), "a == b;");
        assert_eq!(condition_text("b.ne", flags), "a != b;");
    }

    #[test]
    fn tst_records_the_mask_it_tested() {
        // `tst w0, #1` as the specification lowers it: the and into a
        // temporary, the flags written from it. The record says what the
        // and made, tested against zero, so `b.eq` reads the mask.
        let and = Op {
            opcode: OpCode::CPUI_INT_AND,
            out: Some(varnode(
                kuna_base::space::spacetype::IPTR_INTERNAL,
                "unique",
                0x1000,
                4,
            )),
            inputs: vec![
                varnode(
                    kuna_base::space::spacetype::IPTR_PROCESSOR,
                    "register",
                    0x4000,
                    4,
                ),
                varnode(kuna_base::space::spacetype::IPTR_CONSTANT, "const", 1, 4),
            ],
        };
        let flag = Op {
            opcode: OpCode::CPUI_COPY,
            out: Some(varnode(
                kuna_base::space::spacetype::IPTR_PROCESSOR,
                "register",
                0x100,
                1,
            )),
            inputs: vec![varnode(
                kuna_base::space::spacetype::IPTR_INTERNAL,
                "unique",
                0x1000,
                4,
            )],
        };
        let text = with_run(None, |run| {
            let mut scratch = Scratch::default();
            run.run_instruction(0x20000, "tst", &[and, flag], &mut scratch)
                .expect("tst runs");
            let cond = run
                .condition("b.eq", None, 0x20004)
                .expect("b.eq after a tst");
            crate::emit::emit_node(&cond).trim().to_string()
        });
        assert_eq!(text, "(a & 1) == 0;");
    }

    #[test]
    fn a_call_forgets_the_flags() {
        // What the callee compared is not ours: a branch after a call
        // tests flags the lift no longer has, and says so.
        let flags = Flags {
            a: AstNode::var("a"),
            b: AstNode::constant(1, 4),
            dest: None,
        };
        with_run(Some(flags), |run| {
            run.emit_call(0x20000, 0x20008).expect("the call emits");
            assert!(run.flags.is_none(), "the call left flags standing");
        });
    }
}
