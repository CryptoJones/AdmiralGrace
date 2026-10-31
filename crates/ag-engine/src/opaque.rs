//! Opaque predicates: the conditional branches whose condition is decided
//! whatever the input, so one side is always taken and the other never.
//!
//! Two readings find them. The lifted conditions: a comparison of a value
//! with itself, which the lift folds to the constant it is; the arithmetic
//! an obfuscator hides a constant in — `x * (x + 1)` and `x * x + x` are
//! even, `x | 1` is odd and so never 0, an unsigned value is never below
//! 0 — read off the low bit of the expression as a polynomial over the low
//! bits of what it reads, so the order the operands came in does not
//! matter; and a condition over constants alone. The instructions
//! themselves: a block's flags worked out from the constants it moves into
//! registers and the instructions that set the flags to known values —
//! `xor eax, eax; test eax, eax; jnz`, `stc; jc`, `clc; jnc`,
//! `cmp eax, eax; jne` — which needs no lift, so a function the lifter
//! refuses is read too.
//!
//! A branch found is patched out in its own bytes ([`patch`]): an always
//! taken one becomes a `jmp` to the same target, a never taken one as many
//! `nop`s, the length kept either way.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::Mnemonic;

use crate::ast::{AstNode, BinaryOp};
use crate::cfg::ProcedureCfg;
use crate::cpu_context::{Access, DecodedInsn, Flow, Operand, RC_GPR};
use crate::lift::{cc_of, gpr_name, Cc, Stages};
use crate::pipeline::Disasm;
use crate::register::RegisterId;
use crate::structure::Terminator;

/// A conditional branch decided whatever the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opaque {
    /// The address of the conditional branch.
    pub site: u64,
    /// The branch's target.
    pub target: u64,
    /// Whether the branch is always taken; never taken when not.
    pub always: bool,
    /// Why: `x * (x + 1) is always even`, `eax is 0 here`.
    pub why: String,
}

/// The opaque predicates of one function: its graph's blocks read for
/// their flags, and the conditions of its lift when there is one. A branch
/// both find is said once, by the instructions' reason.
pub fn opaque_predicates(
    disasm: &Disasm,
    cfg: &ProcedureCfg,
    stages: Option<&Stages>,
) -> Vec<Opaque> {
    let mut found: BTreeMap<u64, Opaque> = BTreeMap::new();
    for opaque in in_flags(disasm, cfg) {
        found.entry(opaque.site).or_insert(opaque);
    }
    if let Some(stages) = stages {
        for opaque in in_conditions(disasm, stages) {
            found.entry(opaque.site).or_insert(opaque);
        }
    }
    found.into_values().collect()
}

/// The instruction at `address`, when one starts there.
fn instruction_at(disasm: &Disasm, address: u64) -> Option<&DecodedInsn> {
    let index = disasm
        .instructions
        .binary_search_by_key(&address, |ins| ins.address)
        .ok()?;
    disasm.instructions.get(index)
}

/// The branches of the lift's medium level whose condition [`decide`]
/// settles. The site is the conditional jump among the condition's
/// addresses.
pub fn in_conditions(disasm: &Disasm, stages: &Stages) -> Vec<Opaque> {
    let mut found = Vec::new();
    for node in &stages.medium {
        let Terminator::Branch {
            cond, addresses, ..
        } = &node.terminator
        else {
            continue;
        };
        let cond = with_assignments(&node.statements, cond);
        let Some((always, why)) = decide(&cond) else {
            continue;
        };
        let jump = addresses
            .iter()
            .rev()
            .filter_map(|&address| instruction_at(disasm, address))
            .find_map(|ins| match ins.flow {
                Flow::ConditionalBranch(target) => Some((ins.address, target)),
                _ => None,
            });
        if let Some((site, target)) = jump {
            found.push(Opaque {
                site,
                target,
                always,
                why,
            });
        }
    }
    found
}

/// The condition with the variables it reads replaced by what the
/// block's own statements assigned them, where that still stands at the
/// branch: `eax != 0` after `eax = (x + x * x) & 1` is read as the
/// expression. Only an assignment of an expression over variables and
/// constants is carried, and any other statement — a call, a store
/// through a pointer — ends what is carried.
fn with_assignments(statements: &[crate::lift::Statement], cond: &AstNode) -> AstNode {
    let mut held: Vec<(String, AstNode)> = Vec::new();
    for statement in statements {
        match &statement.node {
            AstNode::Assign { lhs, rhs } if matches!(lhs.as_ref(), AstNode::Var { .. }) => {
                let AstNode::Var { name } = lhs.as_ref() else {
                    unreachable!("matched as a variable");
                };
                let value = substitute(rhs, &held);
                held.retain(|(var, expression)| var != name && !expression.reads_var(name));
                let plain = !value.any(&|n| {
                    matches!(
                        n,
                        AstNode::Call { .. }
                            | AstNode::Deref { .. }
                            | AstNode::Assign { .. }
                            | AstNode::Intrinsic { .. }
                    )
                });
                if plain {
                    held.push((name.clone(), value));
                }
            }
            _ => held.clear(),
        }
    }
    substitute(cond, &held)
}

/// `node` with every variable `held` names replaced by its expression, all
/// at once, so an expression put in is not substituted again.
fn substitute(node: &AstNode, held: &[(String, AstNode)]) -> AstNode {
    let sub = |n: &AstNode| Box::new(substitute(n, held));
    match node {
        AstNode::Var { name } => held
            .iter()
            .find(|(var, _)| var == name)
            .map_or_else(|| node.clone(), |(_, expression)| expression.clone()),
        AstNode::Binary { lhs, op, rhs } => AstNode::Binary {
            lhs: sub(lhs),
            op: *op,
            rhs: sub(rhs),
        },
        AstNode::Cast { ty, target } => AstNode::Cast {
            ty: ty.clone(),
            target: sub(target),
        },
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => AstNode::Ternary {
            cond: sub(cond),
            then: sub(then),
            otherwise: sub(otherwise),
        },
        AstNode::ConstantCondition { holds, compared } => AstNode::ConstantCondition {
            holds: *holds,
            compared: sub(compared),
        },
        other => other.clone(),
    }
}

/// One line of C for a node.
fn text(node: &AstNode) -> String {
    crate::emit::emit_node(node)
        .trim_end()
        .trim_end_matches(';')
        .to_string()
}

/// Whether a condition holds whatever the input, and why: `Some(true)`
/// for a condition that always holds, `Some(false)` for one that never
/// does, `None` for one the input decides.
pub fn decide(cond: &AstNode) -> Option<(bool, String)> {
    match cond.clone().folded() {
        AstNode::ConstantCondition { holds, compared } => {
            return Some((
                holds,
                format!("both sides of {} are the same", text(&compared)),
            ));
        }
        AstNode::ConditionTrue => return Some((true, "the carry is clear here".to_string())),
        AstNode::ConditionFalse => return Some((false, "the carry is clear here".to_string())),
        _ => {}
    }
    if let AstNode::Binary { lhs, op, rhs } = cond {
        match op {
            BinaryOp::Equal | BinaryOp::NotEqual => {
                if let Some((equal, why)) = decide_equal(lhs, rhs) {
                    return Some((equal == (*op == BinaryOp::Equal), why));
                }
            }
            BinaryOp::Less | BinaryOp::GreaterEqual | BinaryOp::Greater | BinaryOp::LessEqual => {
                // An unsigned value against 0: never below, always at or
                // above, whichever side the 0 is on.
                let (value, op) = match (zero(rhs), zero(lhs)) {
                    (true, _) => (lhs.as_ref(), *op),
                    (_, true) => (rhs.as_ref(), mirrored(*op)),
                    _ => (lhs.as_ref(), *op),
                };
                if (zero(rhs) || zero(lhs)) && unsigned(value) {
                    let why = format!("{} is unsigned, never below 0", text(value));
                    match op {
                        BinaryOp::GreaterEqual => return Some((true, why)),
                        BinaryOp::Less => return Some((false, why)),
                        _ => {}
                    }
                }
            }
            BinaryOp::LogicalAnd | BinaryOp::LogicalOr => {
                let and = *op == BinaryOp::LogicalAnd;
                let (l, r) = (decide(lhs), decide(rhs));
                // One side that settles the whole settles it; otherwise
                // both sides must.
                for side in [&l, &r].into_iter().flatten() {
                    if side.0 != and {
                        return Some(side.clone());
                    }
                }
                if let (Some((_, a)), Some((_, b))) = (l, r) {
                    return Some((and, format!("{a}, and {b}")));
                }
            }
            _ => {}
        }
    }
    let value = crate::emulate::constant_value(cond)?.value?;
    Some((value != 0, format!("{} is constant", text(cond))))
}

/// Whether a node is the constant 0.
fn zero(node: &AstNode) -> bool {
    matches!(node, AstNode::Constant { value: 0, .. })
}

/// The relation with its sides swapped: `0 > u` is `u < 0`.
fn mirrored(op: BinaryOp) -> BinaryOp {
    match op {
        BinaryOp::Less => BinaryOp::Greater,
        BinaryOp::Greater => BinaryOp::Less,
        BinaryOp::LessEqual => BinaryOp::GreaterEqual,
        BinaryOp::GreaterEqual => BinaryOp::LessEqual,
        other => other,
    }
}

/// Whether a node is read as unsigned: a cast to an unsigned type or a
/// pointer, which is how the lift writes an unsigned comparison.
fn unsigned(node: &AstNode) -> bool {
    match node {
        AstNode::Cast { ty, .. } => {
            let ty = ty.trim();
            ty.starts_with("unsigned") || ty.ends_with('*')
        }
        _ => false,
    }
}

/// Whether `lhs == rhs` whatever the input, and why.
fn decide_equal(lhs: &AstNode, rhs: &AstNode) -> Option<(bool, String)> {
    let (l, r) = (exact(lhs), exact(rhs));
    if let (Some((a, why_a)), Some((b, why_b))) = (&l, &r) {
        // Two constants are the closed evaluation's to say.
        if why_a.is_some() || why_b.is_some() {
            let why = why_a.clone().or_else(|| why_b.clone()).unwrap_or_default();
            return Some((a == b, why));
        }
    }
    // Sides whose low bits always differ are never equal.
    let mut atoms = Atoms::default();
    let difference = parity(lhs, &mut atoms).plus(&parity(rhs, &mut atoms));
    if difference == Poly::one() {
        let why = parity_why(lhs, &mut atoms)
            .or_else(|| parity_why(rhs, &mut atoms))
            .unwrap_or_else(|| {
                format!(
                    "{} is always odd",
                    text(&AstNode::binary(lhs.clone(), BinaryOp::Sub, rhs.clone()))
                )
            });
        return Some((false, why));
    }
    None
}

/// What a node holds whatever the input, when that is known, and the
/// reason when it is not a constant as written: `x * (x + 1) & 1` is 0
/// because `x * (x + 1)` is always even.
fn exact(node: &AstNode) -> Option<(u64, Option<String>)> {
    match node {
        AstNode::Constant { value, .. } => Some((*value, None)),
        // A 0 or a 1 is the same number at any width.
        AstNode::Cast { target, .. } => exact(target).filter(|(value, _)| *value <= 1),
        AstNode::Binary { lhs, op, rhs } => {
            let one = |n: &AstNode| matches!(n, AstNode::Constant { value: 1, .. });
            let two = |n: &AstNode| matches!(n, AstNode::Constant { value: 2, .. });
            match op {
                // The low bit of a value whose low bit is known.
                BinaryOp::And if one(rhs) || one(lhs) => {
                    let subject = if one(rhs) { lhs } else { rhs };
                    let bit = low_bit(subject)?;
                    Some((bit, parity_why(subject, &mut Atoms::default())))
                }
                // An even value has no remainder by 2; an odd one's is 1
                // or -1 by its sign, so it is not known.
                BinaryOp::Mod if two(rhs) => {
                    (low_bit(lhs)? == 0).then(|| (0, parity_why(lhs, &mut Atoms::default())))
                }
                // A value less itself, or exclusive-ored with itself, is 0.
                BinaryOp::Sub | BinaryOp::Xor if lhs == rhs && !effectful(lhs) => {
                    Some((0, Some(format!("{} is always 0", text(node)))))
                }
                BinaryOp::And | BinaryOp::Mul if zero(lhs) || zero(rhs) => {
                    Some((0, Some(format!("{} is always 0", text(node)))))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Whether reading a node twice may give two values: it calls, assigns
/// or runs an intrinsic.
fn effectful(node: &AstNode) -> bool {
    node.any(&|n| {
        matches!(
            n,
            AstNode::Call { .. } | AstNode::Assign { .. } | AstNode::Intrinsic { .. }
        )
    })
}

/// The low bit of a node whatever the input, when it is decided.
fn low_bit(node: &AstNode) -> Option<u64> {
    let poly = parity(node, &mut Atoms::default());
    if poly == Poly::zero() {
        Some(0)
    } else if poly == Poly::one() {
        Some(1)
    } else {
        None
    }
}

/// Why a node's low bit is decided, said of the value inside the `& 1`,
/// the `% 2` and the casts around it: `x * (x + 1) is always even`.
fn parity_why(node: &AstNode, atoms: &mut Atoms) -> Option<String> {
    let mut subject = node;
    loop {
        match subject {
            AstNode::Cast { target, .. } => subject = target,
            AstNode::Binary {
                lhs,
                op: BinaryOp::And,
                rhs,
            } if matches!(rhs.as_ref(), AstNode::Constant { value: 1, .. }) => subject = lhs,
            AstNode::Binary {
                lhs,
                op: BinaryOp::And,
                rhs,
            } if matches!(lhs.as_ref(), AstNode::Constant { value: 1, .. }) => subject = rhs,
            AstNode::Binary {
                lhs,
                op: BinaryOp::Mod,
                rhs,
            } if matches!(rhs.as_ref(), AstNode::Constant { value: 2, .. }) => subject = lhs,
            _ => break,
        }
    }
    // A constant's parity is no news.
    if matches!(subject, AstNode::Constant { .. }) {
        return None;
    }
    let poly = parity(subject, atoms);
    if poly == Poly::zero() {
        Some(format!("{} is always even", text(subject)))
    } else if poly == Poly::one() {
        Some(format!("{} is always odd", text(subject)))
    } else {
        None
    }
}

/// The values a low-bit polynomial is over, each numbered once.
#[derive(Default)]
struct Atoms(Vec<AstNode>);

impl Atoms {
    fn index(&mut self, node: &AstNode) -> usize {
        // Two calls, or two assignments, are two values even when they
        // read the same: each is a value of its own.
        let found = if effectful(node) {
            None
        } else {
            self.0.iter().position(|atom| atom == node)
        };
        match found {
            Some(index) => index,
            None => {
                self.0.push(node.clone());
                self.0.len() - 1
            }
        }
    }
}

/// The low bit of an expression as a polynomial over the low bits of the
/// values it reads, modulo 2: each monomial a product of values (the empty
/// one is 1), the sum their exclusive or. A bit times itself is the bit.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Poly(BTreeSet<BTreeSet<usize>>);

impl Poly {
    fn zero() -> Self {
        Self(BTreeSet::new())
    }

    fn one() -> Self {
        Self(BTreeSet::from([BTreeSet::new()]))
    }

    fn atom(index: usize) -> Self {
        Self(BTreeSet::from([BTreeSet::from([index])]))
    }

    fn plus(&self, other: &Self) -> Self {
        Self(self.0.symmetric_difference(&other.0).cloned().collect())
    }

    fn times(&self, other: &Self) -> Self {
        let mut out = Self::zero();
        for a in &self.0 {
            for b in &other.0 {
                let monomial: BTreeSet<usize> = a.union(b).copied().collect();
                out = out.plus(&Self(BTreeSet::from([monomial])));
            }
        }
        out
    }
}

/// The low bit of `node` as a [`Poly`]. Addition, subtraction and
/// exclusive or add the low bits; multiplication and `&` multiply them;
/// `|` is `a + b + ab`; a remainder by an even constant keeps the low bit,
/// as does a cast; a shift left by a constant clears it. Anything else is
/// a value of its own.
fn parity(node: &AstNode, atoms: &mut Atoms) -> Poly {
    match node {
        AstNode::Constant { value, .. } => {
            if value & 1 == 1 {
                Poly::one()
            } else {
                Poly::zero()
            }
        }
        AstNode::Cast { ty, target } if !ty.contains("bool") && !ty.contains("Bool") => {
            parity(target, atoms)
        }
        AstNode::Binary { lhs, op, rhs } => match op {
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Xor => {
                parity(lhs, atoms).plus(&parity(rhs, atoms))
            }
            BinaryOp::Mul | BinaryOp::And => parity(lhs, atoms).times(&parity(rhs, atoms)),
            BinaryOp::Or => {
                let (a, b) = (parity(lhs, atoms), parity(rhs, atoms));
                a.plus(&b).plus(&a.times(&b))
            }
            BinaryOp::Mod => match rhs.as_ref() {
                AstNode::Constant { value, .. } if *value != 0 && value & 1 == 0 => {
                    parity(lhs, atoms)
                }
                _ => Poly::atom(atoms.index(node)),
            },
            BinaryOp::Shl => match rhs.as_ref() {
                AstNode::Constant { value: 0, .. } => parity(lhs, atoms),
                AstNode::Constant { value, .. } if (1..32).contains(value) => Poly::zero(),
                _ => Poly::atom(atoms.index(node)),
            },
            _ => Poly::atom(atoms.index(node)),
        },
        _ => Poly::atom(atoms.index(node)),
    }
}

/// A flag's value where it is known, and why.
type Known = Option<(bool, String)>;

/// The flags a block's instructions have left known.
#[derive(Debug, Clone, Default)]
struct Flags {
    cf: Known,
    zf: Known,
    sf: Known,
    of: Known,
    pf: Known,
}

/// What a block has put in its registers and its flags, as far as it is
/// known from the block's own instructions.
#[derive(Debug, Clone, Default)]
struct Local {
    /// The general registers, whole, by index.
    regs: BTreeMap<u32, u64>,
    flags: Flags,
}

/// The mask of the low `bits` bits.
fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// A register's name as the listing spells it.
fn reg_name(reg: RegisterId) -> String {
    if reg.bit_offset == 8 {
        return ["ah", "ch", "dh", "bh"]
            .get(reg.index as usize)
            .map_or_else(|| "a high byte".to_string(), |name| name.to_string());
    }
    gpr_name(reg.index, reg.bit_size)
}

impl Local {
    /// The value of a general register at its width, when known.
    fn read(&self, reg: RegisterId) -> Option<u64> {
        if reg.class != RC_GPR {
            return None;
        }
        let whole = self.regs.get(&reg.index)?;
        Some((whole >> reg.bit_offset) & mask(reg.bit_size))
    }

    /// Write a general register at its width: a 32-bit write clears the
    /// upper half, a narrower one keeps the rest when the rest is known.
    fn write(&mut self, reg: RegisterId, value: Option<u64>) {
        if reg.class != RC_GPR {
            return;
        }
        let value = value.map(|value| value & mask(reg.bit_size));
        let whole = match (reg.bit_size, value) {
            (64 | 32, value) => value,
            (_, Some(value)) => self.regs.get(&reg.index).map(|old| {
                let field = mask(reg.bit_size) << reg.bit_offset;
                (old & !field) | (value << reg.bit_offset)
            }),
            (_, None) => None,
        };
        match whole {
            Some(whole) => self.regs.insert(reg.index, whole),
            None => self.regs.remove(&reg.index),
        };
    }

    /// The value of an operand at `bits`, with what it is called, when
    /// known: a register's name, nothing for an immediate.
    fn operand(&self, op: &Operand, bits: u32) -> Option<(u64, Option<String>)> {
        match op {
            Operand::Register(reg) => Some((self.read(*reg)?, Some(reg_name(*reg)))),
            Operand::Imm(imm) => Some(((*imm as u64) & mask(bits), None)),
            Operand::Mem { .. } => None,
        }
    }

    /// Forget what the instruction may have changed: the registers it
    /// writes and the flags it writes.
    fn forget(&mut self, ins: &DecodedInsn) {
        for used in &ins.register_uses {
            if used.access != Access::Read {
                self.write(used.register, None);
            }
        }
        for (bit, flag) in [
            (iced_x86::RflagsBits::CF, &mut self.flags.cf),
            (iced_x86::RflagsBits::ZF, &mut self.flags.zf),
            (iced_x86::RflagsBits::SF, &mut self.flags.sf),
            (iced_x86::RflagsBits::OF, &mut self.flags.of),
            (iced_x86::RflagsBits::PF, &mut self.flags.pf),
        ] {
            if ins.flags_written & bit != 0 {
                *flag = None;
            }
        }
    }

    /// Set the zero, sign and parity flags from a result of `bits` bits.
    fn result_flags(&mut self, result: u64, bits: u32, why: &str) {
        let result = result & mask(bits);
        self.flags.zf = Some((result == 0, why.to_string()));
        self.flags.sf = Some(((result >> (bits - 1)) & 1 == 1, why.to_string()));
        self.flags.pf = Some((
            (result & 0xff).count_ones().is_multiple_of(2),
            why.to_string(),
        ));
    }

    /// Step over one instruction.
    fn step(&mut self, ins: &DecodedInsn) {
        let mnemonic = Mnemonic::try_from(ins.mnemonic as usize).unwrap_or(Mnemonic::INVALID);
        if matches!(
            ins.flow,
            Flow::Call(_) | Flow::IndirectCall | Flow::Syscall | Flow::Interrupt
        ) {
            *self = Self::default();
            return;
        }
        let name = format!("{mnemonic:?}").to_ascii_lowercase();
        match (mnemonic, ins.operands.as_slice()) {
            (Mnemonic::Stc, _) => self.flags.cf = Some((true, "stc sets the carry".to_string())),
            (Mnemonic::Clc, _) => self.flags.cf = Some((false, "clc clears the carry".to_string())),
            (Mnemonic::Cmc, _) => {
                self.flags.cf = self
                    .flags
                    .cf
                    .take()
                    .map(|(cf, why)| (!cf, format!("{why}, and cmc turns it round")))
            }
            (Mnemonic::Mov, [Operand::Register(dest), src]) => {
                let value = self.operand(src, dest.bit_size).map(|(value, _)| value);
                self.write(*dest, value);
            }
            (Mnemonic::Not, [Operand::Register(dest)]) => {
                let value = self.read(*dest).map(|value| !value);
                self.write(*dest, value);
            }
            (
                Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::Cmp
                | Mnemonic::And
                | Mnemonic::Or
                | Mnemonic::Xor
                | Mnemonic::Test,
                [Operand::Register(dest), src],
            ) => self.arith(mnemonic, &name, *dest, src),
            (Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg, [Operand::Register(dest)]) => {
                let bits = dest.bit_size;
                let Some(a) = self.read(*dest) else {
                    let cf = self.flags.cf.take();
                    self.forget(ins);
                    if mnemonic != Mnemonic::Neg {
                        self.flags.cf = cf;
                    }
                    return;
                };
                let min = 1u64 << (bits - 1);
                let (result, of) = match mnemonic {
                    Mnemonic::Inc => (a.wrapping_add(1), a == min - 1),
                    Mnemonic::Dec => (a.wrapping_sub(1), a == min),
                    _ => (a.wrapping_neg(), a == min),
                };
                let why = format!("{} is {} here", reg_name(*dest), signed_text(a, bits));
                self.write(*dest, Some(result));
                self.result_flags(result, bits, &why);
                self.flags.of = Some((of, why.clone()));
                if mnemonic == Mnemonic::Neg {
                    self.flags.cf = Some((a != 0, why));
                }
            }
            _ => self.forget(ins),
        }
    }

    /// Step over a two-operand arithmetic or logical instruction on a
    /// register.
    fn arith(&mut self, mnemonic: Mnemonic, name: &str, dest: RegisterId, src: &Operand) {
        let bits = dest.bit_size;
        let logical = matches!(
            mnemonic,
            Mnemonic::And | Mnemonic::Or | Mnemonic::Xor | Mnemonic::Test
        );
        let writes = !matches!(mnemonic, Mnemonic::Cmp | Mnemonic::Test);
        let same = matches!(src, Operand::Register(reg) if *reg == dest);
        let dest_name = reg_name(dest);
        // The idioms whose flags do not depend on the value: a register
        // less itself or exclusive-ored with itself is 0, compared with
        // itself it is equal.
        if same && matches!(mnemonic, Mnemonic::Sub | Mnemonic::Xor | Mnemonic::Cmp) {
            let why = if mnemonic == Mnemonic::Cmp {
                format!("{dest_name} is compared with itself")
            } else {
                format!("{dest_name} is 0 here")
            };
            if writes {
                self.write(dest, Some(0));
            }
            self.result_flags(0, bits, &why);
            self.flags.cf = Some((false, why.clone()));
            self.flags.of = Some((false, why));
            return;
        }
        let a = self.read(dest);
        let b = self.operand(src, bits);
        let (Some(a), Some((b, b_name))) = (a, b) else {
            if writes {
                self.write(dest, None);
            }
            self.flags = Flags::default();
            // A logical operation clears the carry and the overflow
            // whatever its operands.
            if logical {
                self.flags.cf = Some((false, format!("{name} clears the carry")));
                self.flags.of = Some((false, format!("{name} clears the overflow")));
            }
            return;
        };
        let why = match &b_name {
            Some(b_name) if same => format!("{dest_name} is {} here", signed_text(a, bits)),
            Some(b_name) => format!(
                "{dest_name} is {} and {b_name} is {} here",
                signed_text(a, bits),
                signed_text(b, bits)
            ),
            None => format!("{dest_name} is {} here", signed_text(a, bits)),
        };
        let m = mask(bits);
        let sign = |v: u64| (v >> (bits - 1)) & 1 == 1;
        let (result, cf, of) = match mnemonic {
            Mnemonic::Add => {
                let r = a.wrapping_add(b) & m;
                let carry = (u128::from(a) + u128::from(b)) > u128::from(m);
                (r, carry, sign(a) == sign(b) && sign(r) != sign(a))
            }
            Mnemonic::Sub | Mnemonic::Cmp => {
                let r = a.wrapping_sub(b) & m;
                (r, a < b, sign(a) != sign(b) && sign(r) != sign(a))
            }
            Mnemonic::And | Mnemonic::Test => (a & b, false, false),
            Mnemonic::Or => (a | b, false, false),
            _ => (a ^ b, false, false),
        };
        if writes {
            self.write(dest, Some(result));
        }
        self.result_flags(result, bits, &why);
        self.flags.cf = Some((cf, why.clone()));
        self.flags.of = Some((of, why));
    }

    /// Whether the condition `cc` holds on the flags known, and why.
    fn holds(&self, cc: Cc) -> Option<(bool, String)> {
        let f = &self.flags;
        let not = |k: &Known| k.clone().map(|(v, why)| (!v, why));
        let differ = |a: &Known, b: &Known| match (a, b) {
            (Some((a, x)), Some((b, y))) => Some((a != b, joined(x, y))),
            _ => None,
        };
        let or = |a: Known, b: Known| match (a, b) {
            (Some((true, why)), _) | (_, Some((true, why))) => Some((true, why)),
            (Some((false, x)), Some((false, y))) => Some((false, joined(&x, &y))),
            _ => None,
        };
        let and = |a: Known, b: Known| not(&or(not(&a), not(&b)));
        match cc {
            Cc::E => f.zf.clone(),
            Cc::Ne => not(&f.zf),
            Cc::B => f.cf.clone(),
            Cc::Ae => not(&f.cf),
            Cc::S => f.sf.clone(),
            Cc::Ns => not(&f.sf),
            Cc::P => f.pf.clone(),
            Cc::Np => not(&f.pf),
            Cc::O => f.of.clone(),
            Cc::No => not(&f.of),
            Cc::L => differ(&f.sf, &f.of),
            Cc::Ge => not(&differ(&f.sf, &f.of)),
            Cc::Le => or(f.zf.clone(), differ(&f.sf, &f.of)),
            Cc::G => and(not(&f.zf), not(&differ(&f.sf, &f.of))),
            Cc::Be => or(f.cf.clone(), f.zf.clone()),
            Cc::A => and(not(&f.cf), not(&f.zf)),
        }
    }
}

/// Two reasons as one, said once when they are the same.
fn joined(a: &str, b: &str) -> String {
    if a == b {
        a.to_string()
    } else {
        format!("{a}, and {b}")
    }
}

/// A value of `bits` bits as a signed decimal, hex beside it when large.
fn signed_text(value: u64, bits: u32) -> String {
    let value = value & mask(bits);
    let shift = 64 - bits;
    let signed = ((value << shift) as i64) >> shift;
    if (-9..=9).contains(&signed) {
        signed.to_string()
    } else {
        format!("{value:#x}")
    }
}

/// The conditional branches of the graph whose flags the block they end
/// sets to known values by itself: each block's instructions are stepped
/// over from nothing known, the constants they move and the flags they
/// set followed, and the branch at its end decided where the flags it
/// reads are known.
pub fn in_flags(disasm: &Disasm, cfg: &ProcedureCfg) -> Vec<Opaque> {
    let mut found = Vec::new();
    for block in &cfg.blocks {
        let start = disasm
            .instructions
            .partition_point(|ins| ins.address < block.from);
        let instructions: Vec<&DecodedInsn> = disasm.instructions[start..]
            .iter()
            .take_while(|ins| ins.address < block.to)
            .collect();
        let Some((last, body)) = instructions.split_last() else {
            continue;
        };
        let Flow::ConditionalBranch(target) = last.flow else {
            continue;
        };
        let mut local = Local::default();
        for ins in body {
            local.step(ins);
        }
        let mnemonic = Mnemonic::try_from(last.mnemonic as usize).unwrap_or(Mnemonic::INVALID);
        let decided = match mnemonic {
            Mnemonic::Jrcxz | Mnemonic::Jecxz | Mnemonic::Jcxz => {
                let bits = match mnemonic {
                    Mnemonic::Jrcxz => 64,
                    Mnemonic::Jecxz => 32,
                    _ => 16,
                };
                local.regs.get(&1).map(|rcx| {
                    let value = rcx & mask(bits);
                    (
                        value == 0,
                        format!("{} is {} here", gpr_name(1, bits), signed_text(value, bits)),
                    )
                })
            }
            _ => cc_of(mnemonic, "j").and_then(|cc| local.holds(cc)),
        };
        if let Some((always, why)) = decided {
            found.push(Opaque {
                site: last.address,
                target,
                always,
                why,
            });
        }
    }
    found
}

/// The bytes that patch the conditional branch `ins` out, the length kept,
/// and the instruction they spell: an always taken branch becomes a `jmp`
/// to its target — `EB rel8` in two bytes, `E9 rel32` in five or more —
/// after as many `nop`s as fill the rest, so the jump ends where the
/// branch did and its displacement is the branch's: `0F 8x rel32` becomes
/// `90 E9 rel32`. A never taken one becomes `nop`s. `None` for an
/// instruction that is not a conditional branch, or a target a jump of
/// the length cannot reach.
pub fn patch(ins: &DecodedInsn, always: bool) -> Option<(Vec<u8>, String)> {
    let Flow::ConditionalBranch(target) = ins.flow else {
        return None;
    };
    let len = ins.length;
    if !always {
        let text = if len == 1 {
            "nop".to_string()
        } else {
            format!("nop x{len}")
        };
        return Some((crate::asm::no_ops(len), text));
    }
    let end = ins.address.wrapping_add(len as u64);
    let displacement = target.wrapping_sub(end) as i64;
    let mut bytes;
    if len >= 5 {
        let rel = i32::try_from(displacement).ok()?;
        bytes = crate::asm::no_ops(len - 5);
        bytes.push(0xe9);
        bytes.extend_from_slice(&rel.to_le_bytes());
    } else {
        let rel = i8::try_from(displacement).ok()?;
        if len < 2 {
            return None;
        }
        bytes = crate::asm::no_ops(len - 2);
        bytes.push(0xeb);
        bytes.push(rel as u8);
    }
    Some((bytes, format!("jmp {target:#x}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu_context::X86IcedContext;

    const BASE: u64 = 0x1000;

    fn disasm(bytes: &[u8]) -> Disasm {
        let mut ctx = X86IcedContext::default();
        Disasm::decode(&mut ctx, bytes, BASE).expect("the code decodes")
    }

    /// The opaque predicates the flags of `bytes`, one function at
    /// [`BASE`], decide.
    fn flagged(bytes: &[u8]) -> Vec<(u64, bool, String)> {
        let disasm = disasm(bytes);
        let cfg = crate::cfgwalk::resolve_branches(&disasm, BASE);
        in_flags(&disasm, &cfg)
            .into_iter()
            .map(|o| (o.site, o.always, o.why))
            .collect()
    }

    fn x() -> AstNode {
        AstNode::var("x")
    }

    fn c(value: u64) -> AstNode {
        AstNode::constant(value, 4)
    }

    fn bin(l: AstNode, op: BinaryOp, r: AstNode) -> AstNode {
        AstNode::binary(l, op, r)
    }

    #[test]
    fn a_value_compared_with_itself_is_decided() {
        assert_eq!(
            decide(&bin(x(), BinaryOp::NotEqual, x())),
            Some((false, "both sides of x != x are the same".to_string()))
        );
        assert_eq!(
            decide(&bin(bin(x(), BinaryOp::Sub, x()), BinaryOp::Equal, c(0))),
            Some((true, "x - x is always 0".to_string()))
        );
        assert_eq!(
            decide(&bin(bin(x(), BinaryOp::Xor, x()), BinaryOp::NotEqual, c(0))),
            Some((false, "x ^ x is always 0".to_string()))
        );
        // The lift's own fold, and the carry a logical operation clears.
        let folded = bin(x(), BinaryOp::Equal, x()).folded();
        assert_eq!(decide(&folded).map(|d| d.0), Some(true));
        assert_eq!(decide(&AstNode::ConditionFalse).map(|d| d.0), Some(false));
        // A condition the input decides is not one.
        assert_eq!(decide(&bin(x(), BinaryOp::Equal, c(0))), None);
        assert_eq!(decide(&bin(x(), BinaryOp::Equal, AstNode::var("y"))), None);
    }

    #[test]
    fn a_condition_over_constants_is_constant() {
        assert_eq!(
            decide(&bin(c(5), BinaryOp::Greater, c(3))),
            Some((true, "5 > 3 is constant".to_string()))
        );
    }

    #[test]
    fn a_product_of_consecutive_values_is_even_in_any_order() {
        let even = |e: AstNode| decide(&bin(bin(e, BinaryOp::And, c(1)), BinaryOp::Equal, c(0)));
        // x * (x + 1), (x + 1) * x, x * (x - 1), (1 + x) * x.
        for product in [
            bin(x(), BinaryOp::Mul, bin(x(), BinaryOp::Add, c(1))),
            bin(bin(x(), BinaryOp::Add, c(1)), BinaryOp::Mul, x()),
            bin(x(), BinaryOp::Mul, bin(x(), BinaryOp::Sub, c(1))),
            bin(bin(c(1), BinaryOp::Add, x()), BinaryOp::Mul, x()),
        ] {
            let decided = even(product.clone()).expect("decided");
            assert!(decided.0, "{product:?}");
            assert!(decided.1.ends_with("is always even"), "{}", decided.1);
        }
        assert_eq!(
            even(bin(x(), BinaryOp::Mul, bin(x(), BinaryOp::Add, c(1))))
                .unwrap()
                .1,
            "x * (x + 1) is always even"
        );
        // x * x + x, and x + x * x, under casts and a remainder by 2.
        let sum = bin(bin(x(), BinaryOp::Mul, x()), BinaryOp::Add, x());
        let cast = AstNode::Cast {
            ty: "unsigned int".to_string(),
            target: Box::new(sum.clone()),
        };
        assert_eq!(
            decide(&bin(
                bin(cast, BinaryOp::Mod, c(2)),
                BinaryOp::NotEqual,
                c(0)
            ))
            .map(|d| d.0),
            Some(false)
        );
        let flipped = bin(x(), BinaryOp::Add, bin(x(), BinaryOp::Mul, x()));
        assert_eq!(
            decide(&bin(
                bin(c(1), BinaryOp::And, flipped),
                BinaryOp::Equal,
                c(1)
            ))
            .map(|d| d.0),
            Some(false)
        );
        // Two calls are two values, so f() * (f() + 1) is not decided.
        let call = AstNode::Call {
            callee: Box::new(AstNode::var("f")),
            args: Vec::new(),
        };
        assert_eq!(
            even(bin(
                call.clone(),
                BinaryOp::Mul,
                bin(call.clone(), BinaryOp::Add, c(1))
            )),
            None
        );
        assert_eq!(
            decide(&bin(
                bin(call.clone(), BinaryOp::Sub, call),
                BinaryOp::Equal,
                c(0)
            )),
            None
        );
        // x * x alone is not even, nor x * (x + 2).
        assert_eq!(even(bin(x(), BinaryOp::Mul, x())), None);
        assert_eq!(
            even(bin(x(), BinaryOp::Mul, bin(x(), BinaryOp::Add, c(2)))),
            None
        );
    }

    #[test]
    fn an_odd_value_is_never_zero() {
        let odd = bin(x(), BinaryOp::Or, c(1));
        assert_eq!(
            decide(&bin(odd.clone(), BinaryOp::NotEqual, c(0))),
            Some((true, "x | 1 is always odd".to_string()))
        );
        assert_eq!(
            decide(&bin(c(0), BinaryOp::Equal, odd)).map(|d| d.0),
            Some(false)
        );
        // An odd value's remainder by 2 is not 0, but it is 1 or -1.
        let product = bin(x(), BinaryOp::Mul, bin(x(), BinaryOp::Add, c(1)));
        let plus_one = bin(product, BinaryOp::Add, c(1));
        let remainder = bin(plus_one, BinaryOp::Mod, c(2));
        assert_eq!(
            decide(&bin(remainder.clone(), BinaryOp::Equal, c(0))).map(|d| d.0),
            Some(false)
        );
        assert_eq!(decide(&bin(remainder, BinaryOp::Equal, c(1))), None);
    }

    #[test]
    fn an_unsigned_value_is_never_below_zero() {
        let square = AstNode::Cast {
            ty: "unsigned int".to_string(),
            target: Box::new(bin(x(), BinaryOp::Mul, x())),
        };
        assert_eq!(
            decide(&bin(square.clone(), BinaryOp::GreaterEqual, c(0))),
            Some((
                true,
                "(unsigned int)(x * x) is unsigned, never below 0".to_string()
            ))
        );
        assert_eq!(
            decide(&bin(square.clone(), BinaryOp::Less, c(0))).map(|d| d.0),
            Some(false)
        );
        assert_eq!(
            decide(&bin(c(0), BinaryOp::Greater, square.clone())).map(|d| d.0),
            Some(false)
        );
        // Signed, x * x may wrap below 0.
        assert_eq!(
            decide(&bin(
                bin(x(), BinaryOp::Mul, x()),
                BinaryOp::GreaterEqual,
                c(0)
            )),
            None
        );
        assert_eq!(decide(&bin(square, BinaryOp::Greater, c(0))), None);
    }

    #[test]
    fn a_logical_and_with_a_false_side_never_holds() {
        let never = bin(x(), BinaryOp::NotEqual, x());
        let open = bin(AstNode::var("y"), BinaryOp::Equal, c(3));
        assert_eq!(
            decide(&bin(open.clone(), BinaryOp::LogicalAnd, never.clone())).map(|d| d.0),
            Some(false)
        );
        assert_eq!(decide(&bin(open, BinaryOp::LogicalOr, never)), None);
    }

    #[test]
    fn a_variable_the_block_assigned_is_read_as_its_expression() {
        use crate::lift::Statement;
        let assign = |name: &str, rhs: AstNode| {
            Statement::plain(
                AstNode::Assign {
                    lhs: Box::new(AstNode::var(name)),
                    rhs: Box::new(rhs),
                },
                Vec::new(),
            )
        };
        let sum = bin(bin(x(), BinaryOp::Mul, x()), BinaryOp::Add, x());
        let statements = vec![assign("eax", bin(sum.clone(), BinaryOp::And, c(1)))];
        let cond = bin(AstNode::var("eax"), BinaryOp::NotEqual, c(0));
        let read = with_assignments(&statements, &cond);
        assert_eq!(
            read,
            bin(bin(sum, BinaryOp::And, c(1)), BinaryOp::NotEqual, c(0))
        );
        assert_eq!(decide(&read).map(|d| d.0), Some(false));
        // x = x + 1; y = x: y is the entry's x + 1, once.
        let statements = vec![assign("x", bin(x(), BinaryOp::Add, c(1))), assign("y", x())];
        assert_eq!(
            with_assignments(&statements, &AstNode::var("y")),
            bin(x(), BinaryOp::Add, c(1))
        );
        // An assignment of what x was is dropped when x changes after it.
        let statements = vec![assign("y", x()), assign("x", c(4))];
        assert_eq!(
            with_assignments(&statements, &AstNode::var("y")),
            AstNode::var("y")
        );
    }

    #[test]
    fn a_zeroed_register_tested_never_jumps() {
        // xor eax, eax; test eax, eax; jnz +1; nop; ret
        assert_eq!(
            flagged(&[0x31, 0xc0, 0x85, 0xc0, 0x75, 0x01, 0x90, 0xc3]),
            vec![(0x1004, false, "eax is 0 here".to_string())]
        );
        // mov ecx, 5; cmp ecx, 3; jg +1 (a near one this time); nop; ret
        assert_eq!(
            flagged(&[
                0xb9, 0x05, 0, 0, 0, 0x83, 0xf9, 0x03, 0x0f, 0x8f, 0x01, 0, 0, 0, 0x90, 0xc3
            ]),
            vec![(0x1008, true, "ecx is 5 here".to_string())]
        );
    }

    #[test]
    fn the_carry_set_or_cleared_decides_the_jump_on_it() {
        // stc; jc +1; nop; ret
        assert_eq!(
            flagged(&[0xf9, 0x72, 0x01, 0x90, 0xc3]),
            vec![(0x1001, true, "stc sets the carry".to_string())]
        );
        // clc; jnc +1; nop; ret
        assert_eq!(
            flagged(&[0xf8, 0x73, 0x01, 0x90, 0xc3]),
            vec![(0x1001, true, "clc clears the carry".to_string())]
        );
        // stc; ja +1: the carry alone says not above.
        assert_eq!(
            flagged(&[0xf9, 0x77, 0x01, 0x90, 0xc3]),
            vec![(0x1001, false, "stc sets the carry".to_string())]
        );
    }

    #[test]
    fn a_register_compared_with_itself_is_equal() {
        // cmp rdi, rdi; jne +1; nop; ret
        assert_eq!(
            flagged(&[0x48, 0x39, 0xff, 0x75, 0x01, 0x90, 0xc3]),
            vec![(0x1003, false, "rdi is compared with itself".to_string())]
        );
        // test edi, esi; jb +1: a logical operation clears the carry.
        assert_eq!(
            flagged(&[0x85, 0xf7, 0x72, 0x01, 0x90, 0xc3]),
            vec![(0x1002, false, "test clears the carry".to_string())]
        );
    }

    #[test]
    fn a_value_the_input_decides_or_a_call_forgets_is_not_decided() {
        // test edi, edi; jnz +1; nop; ret
        assert!(flagged(&[0x85, 0xff, 0x75, 0x01, 0x90, 0xc3]).is_empty());
        // xor eax, eax; mov eax, [rdi]; test eax, eax; jz +1; nop; ret
        assert!(flagged(&[0x31, 0xc0, 0x8b, 0x07, 0x85, 0xc0, 0x74, 0x01, 0x90, 0xc3]).is_empty());
        // stc; add edi, 1; jc +1: the add wrote the carry.
        assert!(flagged(&[0xf9, 0x83, 0xc7, 0x01, 0x72, 0x01, 0x90, 0xc3]).is_empty());
    }

    #[test]
    fn a_patch_keeps_the_length_and_the_target() {
        let short = disasm(&[0x75, 0x05]).instructions[0].clone();
        assert_eq!(
            patch(&short, true),
            Some((vec![0xeb, 0x05], "jmp 0x1007".to_string()))
        );
        assert_eq!(
            patch(&short, false),
            Some((vec![0x90, 0x90], "nop x2".to_string()))
        );
        let near = disasm(&[0x0f, 0x85, 0x00, 0x01, 0x00, 0x00]).instructions[0].clone();
        assert_eq!(
            patch(&near, true),
            Some((
                vec![0x90, 0xe9, 0x00, 0x01, 0x00, 0x00],
                "jmp 0x1106".to_string()
            ))
        );
        assert_eq!(patch(&near, false).map(|p| p.0), Some(vec![0x90; 6]));
        // The patched bytes decode as the jump to the same place.
        let (bytes, _) = patch(&near, true).unwrap();
        let patched = disasm(&bytes);
        assert_eq!(
            patched.instructions.last().unwrap().flow,
            Flow::UnconditionalBranch(0x1106)
        );
        let ret = disasm(&[0xc3]).instructions[0].clone();
        assert_eq!(patch(&ret, true), None);
    }
}
