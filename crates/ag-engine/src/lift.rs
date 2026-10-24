//! The lifter: from the decoded x86-64 instructions of one basic block to a
//! C function.
//!
//! This is the first slice of the decompiler, and it is deliberately small.
//! It reads one block of straight-line code — a function of exactly one basic
//! block, ending in `ret` — and anything it does not understand is refused
//! with a reason ([`NotLifted`]) rather than guessed.
//!
//! # How it works
//!
//! The block is walked once, instruction by instruction, with a symbolic
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
//!   when its address is taken (`lea`), or when it is read before it is
//!   written. A partial overwrite of a slot makes its value unknown.
//! * **Parameters** are the argument registers of the calling convention
//!   (System V: `rdi, rsi, rdx, rcx, r8, r9`; Microsoft x64 for a `windows`
//!   language: `rcx, rdx, r8, r9`) that are read before they are written,
//!   named by position: `a`, `b`, `c`… The width of the first read fixes the
//!   type.
//! * **Calls** pass the argument registers written before the call, in
//!   convention order up to the first one not written; the result is `rax`,
//!   and the caller-saved registers are forgotten. A call is a statement of
//!   its own; its result is a temporary (`v1`) that is inlined into the next
//!   statement when that is its only use.
//! * **`ret`** returns `rax` with the width of its last write, or nothing if
//!   `rax` was never written.
//! * **Flags** have no consumer in one straight-line block, so a pure
//!   flag-setter (`cmp`, `test`) is dropped, and `endbr64` and `nop` with it.
//!
//! # The type rule
//!
//! Types come from widths alone: 8 bits is `char`, 16 `short`, 32 `int` and
//! 64 `long`; the unsigned forms appear only in zero-extension casts. Nothing
//! in a `mov` or an `add` says whether a value is signed, so the signed name
//! is the default. An argument register that is passed on but never read has
//! no width here, and is declared `long`.
//!
//! # What is refused
//!
//! More than one block; 32-bit or 16-bit code; a block that does not end in
//! `ret`; any mnemonic outside `mov`, `add`, `sub`, `and`, `or`, `xor`,
//! `lea`, `push`, `pop`, `leave`, `call`, `ret`, `cmp`, `test`, `nop` and
//! `endbr64`; a memory operand that is not a stack slot; an indirect call;
//! a stack the lifter loses track of; and a value that reaches a statement
//! without being known — a register read before it is written that is not an
//! argument register, or one clobbered by a call.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use iced_x86::Mnemonic;

use crate::arch::Bitness;
use crate::ast::{AstNode, BinaryOp};
use crate::cfg::ProcedureCfg;
use crate::cpu_context::{DecodedInsn, Flow, Operand, RC_GPR, RC_IP, RC_NONE};
use crate::pipeline::Disasm;
use crate::register::RegisterId;

/// Why a function was not lifted.
///
/// The reason is a short phrase that completes "not lifted yet: …": the
/// mnemonic the lifter stopped at, the number of blocks, or what it lost
/// track of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotLifted {
    /// What was not lifted.
    pub reason: String,
}

impl NotLifted {
    fn new(reason: impl Into<String>) -> Self {
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
#[derive(Debug, Clone)]
pub struct Statement {
    /// The statement.
    pub node: AstNode,
    /// The addresses of the instructions that went into it, in order.
    pub addresses: Vec<u64>,
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

/// Lift the function at `entry`, when it is one block of straight-line code.
///
/// `names` gives the name of the function at an address, for the calls the
/// body makes; a call to an address with no name is `sub_<hex>`.
pub fn lift_function(
    disasm: &Disasm,
    cfg: &ProcedureCfg,
    entry: u64,
    name: &str,
    bitness: Bitness,
    abi: Abi,
    names: &dyn Fn(u64) -> Option<String>,
) -> Result<LiftedFunction, NotLifted> {
    if bitness != Bitness::Bits64 {
        return Err(NotLifted::new(format!("{bitness} code")));
    }
    let block = match cfg.blocks.len() {
        0 => return Err(NotLifted::new(format!("no code at {entry:#x}"))),
        1 => &cfg.blocks[0],
        n => return Err(NotLifted::new(format!("{n} blocks"))),
    };
    let instructions: Vec<DecodedInsn> = disasm
        .instructions
        .iter()
        .filter(|ins| block.contains(ins.address))
        .cloned()
        .collect();
    lift_block(&instructions, entry, name, abi, names)
}

/// Lift one block of instructions, which must end in `ret`.
pub fn lift_block(
    instructions: &[DecodedInsn],
    entry: u64,
    name: &str,
    abi: Abi,
    names: &dyn Fn(u64) -> Option<String>,
) -> Result<LiftedFunction, NotLifted> {
    let Some(last) = instructions.last() else {
        return Err(NotLifted::new(format!("no code at {entry:#x}")));
    };
    if last.flow != Flow::Return {
        return Err(NotLifted::new(format!(
            "the block ends in {}",
            mnemonic_name(last)
        )));
    }
    let mut lifter = Lifter::new(abi, names);
    for ins in instructions {
        lifter.step(ins)?;
    }
    lifter.finish(name, entry, instructions)
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
}

/// A stack slot: what it holds and how wide it is.
#[derive(Debug, Clone)]
struct Slot {
    bits: u32,
    value: Value,
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
    /// The return.
    Return {
        value: Option<Value>,
        addresses: Vec<u64>,
    },
}

struct Lifter<'a> {
    abi: Abi,
    names: &'a dyn Fn(u64) -> Option<String>,
    /// What each general register holds, by GPR index.
    regs: BTreeMap<u32, Value>,
    /// The stack slots, by offset from the entry stack pointer.
    stack: BTreeMap<i64, Slot>,
    /// The slots whose address was taken.
    address_taken: BTreeSet<i64>,
    /// The slots that are variables, with their width.
    locals: BTreeMap<i64, u32>,
    /// The parameters read so far: position to width.
    params: BTreeMap<usize, u32>,
    temps: Vec<Temp>,
    statements: Vec<Stmt>,
    /// The width of the return value, once `ret` is seen.
    return_bits: Option<u32>,
}

impl<'a> Lifter<'a> {
    fn new(abi: Abi, names: &'a dyn Fn(u64) -> Option<String>) -> Self {
        let mut regs = BTreeMap::new();
        regs.insert(RSP, Value::new(Sym::Stack(0), 64, Vec::new()));
        Self {
            abi,
            names,
            regs,
            stack: BTreeMap::new(),
            address_taken: BTreeSet::new(),
            locals: BTreeMap::new(),
            params: BTreeMap::new(),
            temps: Vec::new(),
            statements: Vec::new(),
            return_bits: None,
        }
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
        let held = match self.regs.get(&index) {
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
        self.regs.insert(index, value.clone());
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
        self.regs.insert(index, value);
        Ok(())
    }

    /// The stack pointer, as an offset from its value at entry.
    fn stack_pointer(&self) -> Result<i64, NotLifted> {
        match self.regs.get(&RSP).map(|value| &value.sym) {
            Some(Sym::Stack(offset)) => Ok(*offset),
            _ => Err(NotLifted::new("the stack pointer is not tracked")),
        }
    }

    fn set_stack_pointer(&mut self, offset: i64, at: u64) {
        self.regs
            .insert(RSP, Value::new(Sym::Stack(offset), 64, vec![at]));
    }

    // ---- the stack --------------------------------------------------------

    /// The slot a memory operand names, when its base is a tracked stack
    /// pointer.
    fn slot_of(&mut self, base: RegisterId, index: RegisterId, disp: i64) -> Option<i64> {
        if index.class != RC_NONE || base.class != RC_GPR {
            return None;
        }
        match self.regs.get(&base.index).map(|value| &value.sym) {
            Some(Sym::Stack(offset)) => Some(offset + disp),
            _ => None,
        }
    }

    /// Why a memory operand is not a stack slot.
    fn not_a_slot(&self, what: &str, base: RegisterId, ins: &DecodedInsn) -> NotLifted {
        match ins.memory_address() {
            Some(address) => NotLifted::new(format!("{what} memory at {address:#x}")),
            None if base.class == RC_GPR => {
                NotLifted::new(format!("{what} {}", gpr_name(base.index, base.bit_size)))
            }
            None => NotLifted::new(format!("{what} memory")),
        }
    }

    /// Load `bits` bits from the slot at `offset`.
    fn load(&mut self, offset: i64, bits: u32, at: u64) -> Value {
        if let Some(slot) = self.stack.get(&offset) {
            if slot.bits == bits {
                return slot.value.clone().also_from(at);
            }
        }
        if self.overlaps(offset, bits) {
            return Value::unknown(
                format!(
                    "the {bits} bits at {} were written in parts",
                    local_name(offset)
                ),
                bits,
            );
        }
        // Never written here: the slot is a variable, read as it is.
        self.locals.entry(offset).or_insert(bits);
        let value = Value::node(AstNode::var(local_name(offset)), bits, vec![at]);
        self.stack.insert(
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
        self.stack.insert(
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

    /// Whether any slot overlaps the `bits` bits at `offset`, other than one
    /// that starts there with that width.
    fn overlaps(&self, offset: i64, bits: u32) -> bool {
        let end = offset + i64::from(bits / 8);
        self.stack.iter().any(|(&start, slot)| {
            let slot_end = start + i64::from(slot.bits / 8);
            start < end && offset < slot_end && !(start == offset && slot.bits == bits)
        })
    }

    /// Forget every slot that overlaps the `bits` bits at `offset`.
    fn kill(&mut self, offset: i64, bits: u32) {
        let end = offset + i64::from(bits / 8);
        self.stack.retain(|&start, slot| {
            let slot_end = start + i64::from(slot.bits / 8);
            !(start < end && offset < slot_end)
        });
    }

    /// Make the slot at `offset` a variable whose address is taken.
    fn take_address(&mut self, offset: i64) -> AstNode {
        self.address_taken.insert(offset);
        let bits = self.stack.get(&offset).map_or(64, |slot| slot.bits);
        self.locals.entry(offset).or_insert(bits);
        AstNode::AddressOf {
            target: Box::new(AstNode::var(local_name(offset))),
        }
    }

    // ---- operands ---------------------------------------------------------

    /// The value of a source operand, read at `bits` bits.
    fn value_of(&mut self, op: &Operand, bits: u32, ins: &DecodedInsn) -> Result<Value, NotLifted> {
        match *op {
            Operand::Register(reg) => self.read(reg, ins.address),
            Operand::Imm(imm) => Ok(Value::node(constant(imm, bits), bits, vec![ins.address])),
            Operand::Mem {
                base, index, disp, ..
            } => match self.slot_of(base, index, disp) {
                Some(offset) => Ok(self.load(offset, bits, ins.address)),
                None => Err(self.not_a_slot("a load from", base, ins)),
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
                base, index, disp, ..
            } => match self.slot_of(base, index, disp) {
                Some(offset) => {
                    self.store(offset, bits, value, ins.address);
                    Ok(())
                }
                None => Err(self.not_a_slot("a store to", base, ins)),
            },
            Operand::Imm(_) => Err(NotLifted::new("a write to an immediate")),
        }
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
        Ok(Value::node(binary(op, lhs, rhs, bits), bits, from))
    }

    // ---- instructions -----------------------------------------------------

    fn step(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let mnemonic = Mnemonic::try_from(ins.mnemonic as usize).unwrap_or(Mnemonic::INVALID);
        match mnemonic {
            // No-ops, and flag-setters with no consumer in one block.
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Cmp | Mnemonic::Test => Ok(()),
            Mnemonic::Mov => self.mov(ins),
            Mnemonic::Add => self.binary_op(BinaryOp::Add, ins),
            Mnemonic::Sub => self.binary_op(BinaryOp::Sub, ins),
            Mnemonic::And => self.binary_op(BinaryOp::And, ins),
            Mnemonic::Or => self.binary_op(BinaryOp::Or, ins),
            Mnemonic::Xor => self.binary_op(BinaryOp::Xor, ins),
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

    fn binary_op(&mut self, op: BinaryOp, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let (dest, src, bits) = self.two(ins)?;
        // `xor eax, eax` and `sub eax, eax` are how a register is zeroed.
        if matches!(op, BinaryOp::Xor | BinaryOp::Sub) && dest == src {
            let zero = Value::node(AstNode::constant(0, bits / 8), bits, vec![ins.address]);
            return self.assign(dest, bits, zero, ins);
        }
        let lhs = self.value_of(dest, bits, ins)?;
        let rhs = self.value_of(src, bits, ins)?;
        let result = self.arith(op, lhs, rhs, bits, ins.address)?;
        self.assign(dest, bits, result, ins)
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
        let mut address = if base.class == RC_IP {
            // The address is the instruction's: what it names is data.
            let target = ins.memory_address().unwrap_or(disp as u64);
            Value::node(AstNode::constant(target, bits / 8), bits, vec![at])
        } else if base.class == RC_GPR {
            self.read(RegisterId::new(RC_GPR, base.index, bits), at)?
        } else if base.class == RC_NONE {
            Value::node(constant(0, bits), bits, vec![at])
        } else {
            return Err(NotLifted::new("lea with a segment base"));
        };
        if index.class != RC_NONE {
            let mut scaled = self.read(RegisterId::new(RC_GPR, index.index, bits), at)?;
            if scale > 1 {
                let factor = Value::node(constant(i128::from(scale), bits), bits, vec![at]);
                scaled = self.arith(BinaryOp::Mul, scaled, factor, bits, at)?;
            }
            address = self.arith(BinaryOp::Add, address, scaled, bits, at)?;
        }
        if disp != 0 && base.class != RC_IP {
            let offset = Value::node(constant(i128::from(disp), bits), bits, vec![at]);
            address = self.arith(BinaryOp::Add, address, offset, bits, at)?;
        }
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
        self.regs.insert(RSP, frame);
        let offset = self.stack_pointer()?;
        let value = self.load(offset, 64, ins.address);
        self.set_stack_pointer(offset + 8, ins.address);
        self.regs.insert(RBP, value);
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
            let Some(value) = self.regs.get(&register).cloned() else {
                break;
            };
            if matches!(value.sym, Sym::Unknown(_)) {
                break;
            }
            let value = self.at_width(value.clone(), value.bits, register, at)?;
            addresses.extend(value.from.iter().copied());
            args.push(self.node_of(&value)?);
        }
        let name = (self.names)(target).unwrap_or_else(|| format!("sub_{target:x}"));
        let node = AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name,
                address: target,
            }),
            args,
        };
        // The call clobbers the caller-saved registers and anything on the
        // stack a pointer was taken to.
        for index in 0..16 {
            if !self.abi.is_callee_saved(index) {
                self.regs.insert(
                    index,
                    Value::unknown(
                        format!("{} after the call at {at:#x}", gpr_name(index, 64)),
                        64,
                    ),
                );
            }
        }
        let temp = self.temps.len();
        self.temps.push(Temp {
            name: format!("v{}", temp + 1),
            bits: None,
        });
        self.regs
            .insert(RAX, Value::new(Sym::Temp(temp), 64, vec![at]));
        for &offset in &self.address_taken {
            if let Some(slot) = self.stack.get_mut(&offset) {
                slot.value = Value::node(AstNode::var(local_name(offset)), slot.bits, vec![at]);
            }
        }
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
        let value = match self.regs.get(&RAX).cloned() {
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
            self.return_bits = Some(value.bits);
        }
        self.statements.push(Stmt::Return {
            value,
            addresses: sorted(addresses),
        });
        Ok(())
    }

    // ---- the function -----------------------------------------------------

    fn finish(
        mut self,
        name: &str,
        entry: u64,
        instructions: &[DecodedInsn],
    ) -> Result<LiftedFunction, NotLifted> {
        // Resolve every statement to a node, keeping the stores to the slots
        // that became variables. Resolving a statement can take the address
        // of a slot — a pointer into the frame reaching a call or the return
        // — which makes earlier stores to it statements too, so this runs
        // until no more addresses are taken.
        let statements = std::mem::take(&mut self.statements);
        let resolved = loop {
            let taken = self.address_taken.len();
            let resolved = self.resolve(&statements)?;
            if self.address_taken.len() == taken {
                break resolved;
            }
        };

        // A call result used once, by the very next statement, is inlined
        // there; one used elsewhere becomes a declared temporary; one never
        // used leaves the call as a statement of its own.
        let mut body: Vec<Statement> = Vec::new();
        let mut temps: Vec<Variable> = Vec::new();
        let mut pending: Option<(usize, AstNode, Vec<u64>)> = None;
        for (i, (temp, node, addresses)) in resolved.iter().enumerate() {
            let mut node = node.clone();
            let mut addresses = addresses.clone();
            if let Some((temp, call, call_addresses)) = pending.take() {
                let name = self.temps[temp].name.clone();
                if node.reads_var(&name) {
                    node = node.substitute(&name, &call);
                    addresses.extend(call_addresses);
                    addresses = sorted(addresses);
                } else {
                    unreachable!("a pending call is only kept when the next statement reads it");
                }
            }
            match temp {
                Some(temp) => {
                    let temp = *temp;
                    let name = self.temps[temp].name.clone();
                    let uses = resolved
                        .iter()
                        .enumerate()
                        .filter(|(j, (_, other, _))| *j != i && other.reads_var(&name))
                        .count();
                    let next_reads = resolved
                        .get(i + 1)
                        .is_some_and(|(_, next, _)| next.reads_var(&name));
                    if uses == 0 {
                        body.push(Statement { node, addresses });
                    } else if uses == 1 && next_reads {
                        pending = Some((temp, node, addresses));
                    } else {
                        let bits = self.temps[temp].bits.unwrap_or(64);
                        temps.push(Variable {
                            ty: type_name(bits).to_string(),
                            name: name.clone(),
                        });
                        body.push(Statement {
                            node: AstNode::Assign {
                                lhs: Box::new(AstNode::var(name)),
                                rhs: Box::new(node),
                            },
                            addresses,
                        });
                    }
                }
                None => body.push(Statement { node, addresses }),
            }
        }

        let params = (0..self.params.keys().next_back().map_or(0, |last| last + 1))
            .map(|position| Variable {
                ty: self
                    .params
                    .get(&position)
                    .map_or("long", |&bits| type_name(bits))
                    .to_string(),
                name: parameter_name(position),
            })
            .collect();

        // The locals nearest the frame first, then the temporaries.
        let mut locals: Vec<Variable> = self
            .locals
            .iter()
            .rev()
            .map(|(&offset, &bits)| Variable {
                ty: type_name(bits).to_string(),
                name: local_name(offset),
            })
            .collect();
        locals.extend(temps);

        let claimed: BTreeSet<u64> = body
            .iter()
            .flat_map(|s| s.addresses.iter().copied())
            .collect();
        let frame = instructions
            .iter()
            .map(|ins| ins.address)
            .filter(|address| !claimed.contains(address))
            .collect();

        Ok(LiftedFunction {
            name: name.to_string(),
            address: entry,
            return_type: self.return_bits.map_or("void", type_name).to_string(),
            params,
            locals,
            body,
            frame,
        })
    }
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
                    if !self.address_taken.contains(offset) {
                        if self.address_taken.iter().any(|&taken| {
                            taken < offset + i64::from(bits / 8)
                                && *offset < taken + i64::from(self.locals[&taken] / 8)
                        }) {
                            return Err(NotLifted::new(format!(
                                "a partial write to {}",
                                local_name(*offset)
                            )));
                        }
                        continue;
                    }
                    self.locals.entry(*offset).or_insert(*bits);
                    let rhs = self.node_of(value)?;
                    let node = AstNode::Assign {
                        lhs: Box::new(AstNode::var(local_name(*offset))),
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

/// `lhs op rhs`, with a negative constant on the right folded into the
/// opposite operation: `a + -8` is `a - 8`.
fn binary(op: BinaryOp, lhs: AstNode, rhs: AstNode, bits: u32) -> AstNode {
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

/// The name of the stack slot at `offset` from the entry stack pointer.
fn local_name(offset: i64) -> String {
    if offset < 0 {
        format!("local_{:x}", -offset)
    } else {
        format!("stack_{offset:x}")
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
        lift_block(&decode(bytes), BASE, "f", Abi::SystemV, &names)
    }

    /// The C of `bytes`, or the reason it was not lifted.
    fn c(bytes: &[u8]) -> String {
        match lift(bytes) {
            Ok(function) => emit_function(&function).text(),
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
            emit_function(&function).text(),
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
            emit_function(&function).text(),
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
    fn flag_setters_with_no_consumer_are_dropped() {
        // mov eax, edi; cmp eax, esi; test eax, eax; ret. The cmp reads esi,
        // but a dropped instruction makes no parameter.
        assert_eq!(
            c(&[0x89, 0xf8, 0x39, 0xf0, 0x85, 0xc0, 0xc3]),
            "int f(int a)\n{\n  return a;\n}"
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
        // mov eax, edi; cdqe; ret
        assert_eq!(
            refused(&[0x89, 0xf8, 0x48, 0x98, 0xc3]),
            "not lifted yet: cdqe"
        );
        // imul eax, esi
        assert_eq!(refused(&[0x0f, 0xaf, 0xc6, 0xc3]), "not lifted yet: imul");
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
    fn a_load_through_a_pointer_register_is_refused() {
        // mov eax, [rdi]; ret
        assert_eq!(
            refused(&[0x8b, 0x07, 0xc3]),
            "not lifted yet: a load from rdi"
        );
        // mov eax, [rip+0x10]; ret
        assert_eq!(
            refused(&[0x8b, 0x05, 0x10, 0, 0, 0, 0xc3]),
            "not lifted yet: a load from memory at 0x1016"
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
        )
        .expect("lifts");
        assert_eq!(
            emit_function(&function).text(),
            "int add(int a, int b)\n{\n  return a + b;\n}"
        );
    }

    #[test]
    fn the_convention_comes_from_the_language() {
        assert_eq!(Abi::of_language("x86:LE:64:default:windows"), Abi::Win64);
        assert_eq!(Abi::of_language("x86:LE:64:default:gcc"), Abi::SystemV);
        assert_eq!(Abi::of_language("x86:LE:32:default:gcc"), Abi::SystemV);
    }

    #[test]
    fn only_a_function_of_one_block_is_lifted() {
        // jmp +0 (to the next instruction, a leader); ret
        let instructions = decode(&[0xeb, 0x00, 0xc3]);
        let disasm = Disasm {
            file_offset_of_segment: 0,
            instructions,
        };
        let cfg = crate::cfgwalk::resolve_branches(&disasm, BASE);
        assert_eq!(cfg.blocks.len(), 2);
        let error = lift_function(
            &disasm,
            &cfg,
            BASE,
            "f",
            Bitness::Bits64,
            Abi::SystemV,
            &names,
        )
        .expect_err("two blocks are refused");
        assert_eq!(error.to_string(), "not lifted yet: 2 blocks");

        let error = lift_function(
            &disasm,
            &cfg,
            BASE,
            "f",
            Bitness::Bits32,
            Abi::SystemV,
            &names,
        )
        .expect_err("32-bit code is refused");
        assert_eq!(error.to_string(), "not lifted yet: 32-bit code");
    }

    #[test]
    fn the_signature_line_stands_for_the_entry_and_the_frame() {
        // push rbp; mov rbp, rsp; mov eax, edi; pop rbp; ret
        let function = lift(&[0x55, 0x48, 0x89, 0xe5, 0x89, 0xf8, 0x5d, 0xc3]).expect("lifts");
        let pseudocode = emit_function(&function);
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
}
