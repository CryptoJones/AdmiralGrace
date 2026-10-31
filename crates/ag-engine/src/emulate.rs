//! An emulator over the medium level: a function's statements over
//! variables, run on the block graph the lifter built, against the image's
//! memory, without a debugger. Values are the machine's words; what the
//! emulator cannot know — a call it cannot follow, a local nothing wrote, a
//! load from memory the image does not have — is unknown, and a branch,
//! a return or an address that depends on an unknown stops the run and
//! says why. A plugin's rewriter has already had the graph, as has an
//! architecture that lifts its own.

use std::collections::BTreeMap;

use crate::ast::{AstNode, BinaryOp};
use crate::lift::Stages;
use crate::structure::{Node, Terminator};

/// What the emulator reads memory and calls from: the image.
pub trait World {
    /// The bytes at `address`, when the image has them.
    fn read(&self, address: u64, len: usize) -> Option<Vec<u8>>;
    /// The address of a datum the lift names.
    fn address_of(&self, name: &str) -> Option<u64>;
    /// The width in bytes of a datum the lift names, when known.
    fn size_of(&self, _name: &str) -> Option<u64> {
        None
    }
    /// A call to the function `name` at `address` with `args`, `depth`
    /// calls deep: the value it returns, or `None` when the call cannot be
    /// followed, which leaves its result unknown.
    fn call(&self, _name: &str, _address: u64, _args: &[Val], _depth: usize) -> Option<Val> {
        None
    }
}

/// How far a run goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The statements run before the run is stopped.
    pub steps: usize,
    /// How many calls deep the emulator follows.
    pub depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            steps: 10_000,
            depth: 8,
        }
    }
}

/// A value: a machine word with the width and signedness its type gives
/// it, or unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Val {
    /// The bits, masked to `bits`; `None` when unknown.
    pub value: Option<u64>,
    pub bits: u32,
    pub signed: bool,
}

impl Val {
    pub fn known(value: u64, bits: u32, signed: bool) -> Self {
        Self {
            value: Some(value & mask(bits)),
            bits,
            signed,
        }
    }

    pub fn unknown(bits: u32, signed: bool) -> Self {
        Self {
            value: None,
            bits,
            signed,
        }
    }

    /// The value as a signed number, by its width.
    pub fn as_i64(&self) -> Option<i64> {
        self.value.map(|value| sign_extend(value, self.bits))
    }

    /// The value converted to another type.
    fn cast(self, bits: u32, signed: bool) -> Self {
        let value = self.value.map(|value| {
            let wide = if self.signed {
                sign_extend(value, self.bits) as u64
            } else {
                value
            };
            wide & mask(bits)
        });
        Self {
            value,
            bits,
            signed,
        }
    }

    /// The value as text: decimal, with the hex beside it when it is wide.
    pub fn text(&self) -> String {
        match self.value {
            None => "unknown".to_string(),
            Some(value) => {
                let shown = if self.signed {
                    sign_extend(value, self.bits).to_string()
                } else {
                    value.to_string()
                };
                if value > 9 {
                    format!("{shown} ({value:#x})")
                } else {
                    shown
                }
            }
        }
    }
}

fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    if bits >= 64 {
        value as i64
    } else {
        let shift = 64 - bits;
        (((value & mask(bits)) << shift) as i64) >> shift
    }
}

/// The width in bits and the signedness of a C type the lift spells:
/// `int`, `unsigned long`, `char`, `short`, `int *`.
pub fn type_of(ty: &str) -> (u32, bool) {
    let ty = ty.trim();
    if ty.ends_with('*') {
        return (64, false);
    }
    let unsigned = ty.starts_with("unsigned");
    let base = ty.trim_start_matches("unsigned").trim();
    let bits = match base {
        "char" | "_Bool" | "bool" => 8,
        "short" => 16,
        "int" => 32,
        "long" | "long long" | "" => 64,
        _ => 64,
    };
    (bits, !unsigned)
}

/// Why a run stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The function returned, with its value when it has one.
    Returned(Option<Val>),
    /// The step limit was reached.
    Steps(usize),
    /// Something the run depended on was unknown, at the statement given.
    Unknown { at: Option<u64>, what: String },
    /// The graph went to no block.
    NoBlock(usize),
}

impl Stop {
    /// The stop as text.
    pub fn text(&self) -> String {
        match self {
            Stop::Returned(Some(value)) => format!("returned {}", value.text()),
            Stop::Returned(None) => "returned".to_string(),
            Stop::Steps(steps) => format!("stopped after {steps} steps"),
            Stop::Unknown { at: Some(at), what } => format!("stopped at {at:#x}: {what}"),
            Stop::Unknown { at: None, what } => format!("stopped: {what}"),
            Stop::NoBlock(block) => format!("stopped: no block {block}"),
        }
    }
}

/// One statement run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The first address the statement came from.
    pub address: Option<u64>,
    /// The block it is in.
    pub block: usize,
    /// The statement, as the medium level prints it.
    pub text: String,
    /// What it wrote, when it wrote a variable: the name and the value.
    pub wrote: Option<(String, Val)>,
    /// A note: a call not followed, a load from memory the image lacks.
    pub note: Option<String>,
}

/// A run of a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// The function's name.
    pub name: String,
    pub address: u64,
    /// The statements run, in order.
    pub steps: Vec<Step>,
    /// Every variable at the end: parameters, then locals, by name.
    pub variables: BTreeMap<String, Val>,
    /// The bytes the run wrote to memory, by address.
    pub memory: BTreeMap<u64, u8>,
    pub stop: Stop,
}

impl Run {
    /// The value returned, when the run returned one.
    pub fn returned(&self) -> Option<Val> {
        match &self.stop {
            Stop::Returned(value) => *value,
            _ => None,
        }
    }

    /// The run as text: each step with its address and what it wrote, then
    /// the stop and the variables.
    pub fn text(&self) -> String {
        let mut out = format!("; {} at {:#x}: emulated\n", self.name, self.address);
        for step in &self.steps {
            let at = match step.address {
                Some(address) => format!("{address:08x}"),
                None => "        ".to_string(),
            };
            out.push_str(&format!("  {at}  {}", step.text));
            if let Some((name, value)) = &step.wrote {
                out.push_str(&format!("  ; {name} = {}", value.text()));
            }
            if let Some(note) = &step.note {
                out.push_str(&format!("  ; {note}"));
            }
            out.push('\n');
        }
        out.push_str(&format!("; {}\n", self.stop.text()));
        for (name, value) in &self.variables {
            out.push_str(&format!(";   {name} = {}\n", value.text()));
        }
        out
    }
}

/// Run the function of `stages` with `args` as its parameters, in order,
/// against `world`, within `limits`.
pub fn run(stages: &Stages, args: &[u64], world: &dyn World, limits: &Limits) -> Run {
    run_at_depth(stages, args, world, limits, 0)
}

/// [`run`], `depth` calls deep.
pub fn run_at_depth(
    stages: &Stages,
    args: &[u64],
    world: &dyn World,
    limits: &Limits,
    depth: usize,
) -> Run {
    let mut machine = Machine {
        variables: BTreeMap::new(),
        types: BTreeMap::new(),
        memory: BTreeMap::new(),
        world,
        depth,
        limits,
        steps: Vec::new(),
    };
    for variable in stages.function.params.iter().chain(&stages.function.locals) {
        let (bits, signed) = type_of(&variable.ty);
        machine.types.insert(variable.name.clone(), (bits, signed));
    }
    for (variable, arg) in stages.function.params.iter().zip(args) {
        let (bits, signed) = type_of(&variable.ty);
        machine
            .variables
            .insert(variable.name.clone(), Val::known(*arg, bits, signed));
    }
    for variable in stages.function.params.iter().skip(args.len()) {
        let (bits, signed) = type_of(&variable.ty);
        machine
            .variables
            .insert(variable.name.clone(), Val::unknown(bits, signed));
    }
    let stop = machine.walk(&stages.medium, 0);
    let mut variables = machine.variables;
    for variable in stages.function.params.iter().chain(&stages.function.locals) {
        let (bits, signed) = type_of(&variable.ty);
        variables
            .entry(variable.name.clone())
            .or_insert_with(|| Val::unknown(bits, signed));
    }
    Run {
        name: stages.function.name.clone(),
        address: stages.function.address,
        steps: machine.steps,
        variables,
        memory: machine.memory,
        stop,
    }
}

/// What stops an evaluation short.
#[derive(Debug)]
struct Why(String);

struct Machine<'a> {
    variables: BTreeMap<String, Val>,
    types: BTreeMap<String, (u32, bool)>,
    memory: BTreeMap<u64, u8>,
    world: &'a dyn World,
    depth: usize,
    limits: &'a Limits,
    steps: Vec<Step>,
}

impl Machine<'_> {
    /// Run the graph from `entry`.
    fn walk(&mut self, nodes: &[Node], entry: usize) -> Stop {
        let mut block = entry;
        let mut count = 0usize;
        loop {
            let Some(node) = nodes.get(block) else {
                return Stop::NoBlock(block);
            };
            for statement in &node.statements {
                if count >= self.limits.steps {
                    return Stop::Steps(count);
                }
                count += 1;
                let address = statement.addresses.iter().min().copied();
                let text = crate::emit::emit_node(&statement.node)
                    .trim_end()
                    .trim_end_matches(';')
                    .to_string();
                let mut step = Step {
                    address,
                    block,
                    text,
                    wrote: None,
                    note: None,
                };
                match &statement.node {
                    AstNode::Return { value } => {
                        let returned = match value {
                            Some(value) => match self.eval(value) {
                                Ok(value) => Some(value),
                                Err(Why(what)) => {
                                    self.steps.push(step);
                                    return Stop::Unknown { at: address, what };
                                }
                            },
                            None => None,
                        };
                        self.steps.push(step);
                        return Stop::Returned(returned);
                    }
                    node => {
                        if let Err(Why(what)) = self.execute(node, &mut step) {
                            self.steps.push(step);
                            return Stop::Unknown { at: address, what };
                        }
                        self.steps.push(step);
                    }
                }
            }
            match &node.terminator {
                Terminator::Return => return Stop::Returned(None),
                Terminator::Goto { target, .. } => block = *target,
                Terminator::Branch {
                    cond,
                    taken,
                    next,
                    addresses,
                } => {
                    let at = addresses.iter().min().copied().or_else(|| {
                        node.statements
                            .last()
                            .and_then(|s| s.addresses.iter().min().copied())
                    });
                    match self.eval(cond) {
                        Ok(Val {
                            value: Some(value), ..
                        }) => block = if value != 0 { *taken } else { *next },
                        Ok(_) => {
                            return Stop::Unknown {
                                at,
                                what: format!(
                                    "the branch on {} depends on an unknown value",
                                    one_line(cond)
                                ),
                            }
                        }
                        Err(Why(what)) => return Stop::Unknown { at, what },
                    }
                }
                Terminator::Switch {
                    index,
                    cases,
                    addresses,
                } => {
                    let at = addresses.iter().min().copied().or_else(|| {
                        node.statements
                            .last()
                            .and_then(|s| s.addresses.iter().min().copied())
                    });
                    let value = match self.eval(index) {
                        Ok(Val {
                            value: Some(value),
                            bits,
                            ..
                        }) => sign_extend(value, bits),
                        Ok(_) => {
                            return Stop::Unknown {
                                at,
                                what: format!(
                                    "the switch on {} depends on an unknown value",
                                    one_line(index)
                                ),
                            }
                        }
                        Err(Why(what)) => return Stop::Unknown { at, what },
                    };
                    match cases
                        .iter()
                        .find(|(values, _)| values.contains(&value))
                        .map(|(_, target)| *target)
                    {
                        Some(target) => block = target,
                        None => {
                            return Stop::Unknown {
                                at,
                                what: format!("no case of the switch takes {value}"),
                            }
                        }
                    }
                }
            }
        }
    }

    /// Run one statement.
    fn execute(&mut self, node: &AstNode, step: &mut Step) -> Result<(), Why> {
        match node {
            AstNode::Assign { lhs, rhs } => {
                let value = self.eval(rhs)?;
                match lhs.as_ref() {
                    AstNode::Var { name } => {
                        let (bits, signed) = self
                            .types
                            .get(name)
                            .copied()
                            .unwrap_or((value.bits, value.signed));
                        let stored = value.cast(bits, signed);
                        if self.types.contains_key(name) {
                            self.variables.insert(name.clone(), stored);
                        } else if let Some(address) = self.world.address_of(name) {
                            // A global the lift names.
                            self.store(address, stored)?;
                        } else {
                            self.variables.insert(name.clone(), stored);
                        }
                        step.wrote = Some((name.clone(), stored));
                    }
                    AstNode::Deref { target } => {
                        let (address, bits, signed) = self.pointer(target)?;
                        let Some(address) = address.value else {
                            return Err(Why(format!(
                                "the store through {} goes to an unknown address",
                                one_line(target)
                            )));
                        };
                        self.store(address, value.cast(bits, signed))?;
                        step.note = Some(format!(
                            "wrote {} at {address:#x}",
                            value.cast(bits, signed).text()
                        ));
                    }
                    other => {
                        return Err(Why(format!("a store to {}", one_line(other))));
                    }
                }
                Ok(())
            }
            AstNode::Call { .. } | AstNode::Intrinsic { .. } => {
                let value = self.eval(node)?;
                if value.value.is_none() {
                    step.note = Some("not followed; its result is unknown".to_string());
                }
                Ok(())
            }
            AstNode::Label { .. } | AstNode::Goto { .. } | AstNode::Break | AstNode::Continue => {
                Ok(())
            }
            other => {
                // An expression for its effects alone.
                self.eval(other).map(|_| ())
            }
        }
    }

    /// A pointer's address and the width and signedness of what it points
    /// at: `(int *)p` is `p`, 32 bits, signed; a bare pointer 64 bits.
    fn pointer(&mut self, target: &AstNode) -> Result<(Val, u32, bool), Why> {
        match target {
            AstNode::Cast { ty, target } if ty.trim_end().ends_with('*') => {
                let pointee = ty.trim_end().trim_end_matches('*');
                let (bits, signed) = type_of(pointee);
                Ok((self.eval(target)?, bits, signed))
            }
            other => Ok((self.eval(other)?, 64, true)),
        }
    }

    fn store(&mut self, address: u64, value: Val) -> Result<(), Why> {
        let Some(bits) = value.value else {
            return Err(Why(format!("an unknown value stored at {address:#x}")));
        };
        for (index, byte) in bits
            .to_le_bytes()
            .iter()
            .enumerate()
            .take((value.bits / 8) as usize)
        {
            self.memory
                .insert(address.wrapping_add(index as u64), *byte);
        }
        Ok(())
    }

    fn load(&self, address: u64, bits: u32, signed: bool) -> Val {
        let len = (bits / 8).max(1) as usize;
        let mut bytes = Vec::with_capacity(len);
        let image = self.world.read(address, len);
        for index in 0..len {
            let at = address.wrapping_add(index as u64);
            match self.memory.get(&at) {
                Some(byte) => bytes.push(*byte),
                None => match image.as_ref().and_then(|image| image.get(index)) {
                    Some(byte) => bytes.push(*byte),
                    None => return Val::unknown(bits, signed),
                },
            }
        }
        let mut word = [0u8; 8];
        word[..len].copy_from_slice(&bytes);
        Val::known(u64::from_le_bytes(word), bits, signed)
    }

    /// Evaluate an expression.
    fn eval(&mut self, node: &AstNode) -> Result<Val, Why> {
        Ok(match node {
            AstNode::Constant { value, width_bytes } => Val::known(*value, width_bytes * 8, true),
            AstNode::Var { name } => match self.variables.get(name) {
                Some(value) => *value,
                None => match self.world.address_of(name) {
                    // A global: read from the image at the width its symbol says.
                    Some(address) => {
                        let bits = self
                            .world
                            .size_of(name)
                            .filter(|size| matches!(size, 1 | 2 | 4 | 8))
                            .map_or(64, |size| size as u32 * 8);
                        self.load(address, bits, true)
                    }
                    None => {
                        let (bits, signed) = self.types.get(name).copied().unwrap_or((64, true));
                        Val::unknown(bits, signed)
                    }
                },
            },
            AstNode::Register { reg } => Val::unknown(reg.bit_size, true),
            AstNode::StringLiteral { .. } | AstNode::FunctionName { .. } => Val::unknown(64, false),
            AstNode::ConditionTrue => Val::known(1, 8, false),
            AstNode::ConditionFalse => Val::known(0, 8, false),
            AstNode::ConstantCondition { holds, .. } => Val::known(u64::from(*holds), 8, false),
            AstNode::Cast { ty, target } => {
                let (bits, signed) = type_of(ty);
                self.eval(target)?.cast(bits, signed)
            }
            AstNode::Deref { target } => {
                let (address, bits, signed) = self.pointer(target)?;
                match address.value {
                    Some(address) => self.load(address, bits, signed),
                    None => Val::unknown(bits, signed),
                }
            }
            AstNode::AddressOf { target } => match target.as_ref() {
                AstNode::Var { name } => match self.world.address_of(name) {
                    Some(address) => Val::known(address, 64, false),
                    None => Val::unknown(64, false),
                },
                _ => Val::unknown(64, false),
            },
            AstNode::Ternary {
                cond,
                then,
                otherwise,
            } => {
                let cond = self.eval(cond)?;
                let (then, otherwise) = (self.eval(then)?, self.eval(otherwise)?);
                match cond.value {
                    Some(0) => otherwise,
                    Some(_) => then,
                    None => Val::unknown(then.bits, then.signed),
                }
            }
            AstNode::Binary { lhs, op, rhs } => {
                let l = self.eval(lhs)?;
                let r = self.eval(rhs)?;
                binary(*op, l, r)?
            }
            AstNode::Assign { lhs, rhs } => {
                let mut step = Step {
                    address: None,
                    block: 0,
                    text: String::new(),
                    wrote: None,
                    note: None,
                };
                self.execute(
                    &AstNode::Assign {
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                    },
                    &mut step,
                )?;
                step.wrote
                    .map_or(Val::unknown(64, true), |(_, value)| value)
            }
            AstNode::Call { callee, args } => {
                let mut values = Vec::with_capacity(args.len());
                for arg in args {
                    values.push(self.eval(arg)?);
                }
                match callee.as_ref() {
                    AstNode::FunctionName { name, address } if self.depth < self.limits.depth => {
                        self.world
                            .call(name, *address, &values, self.depth + 1)
                            .unwrap_or_else(|| Val::unknown(64, true))
                    }
                    _ => Val::unknown(64, true),
                }
            }
            AstNode::Intrinsic { args, .. } => {
                for arg in args {
                    self.eval(arg)?;
                }
                Val::unknown(64, true)
            }
            AstNode::Return { value } => match value {
                Some(value) => self.eval(value)?,
                None => Val::unknown(64, true),
            },
            AstNode::If { .. }
            | AstNode::IfGoto { .. }
            | AstNode::Loop { .. }
            | AstNode::Label { .. }
            | AstNode::Goto { .. }
            | AstNode::Break
            | AstNode::Continue => Val::unknown(64, true),
        })
    }
}

/// An operator over two values: unknown when either is, the width the
/// wider operand's, the comparisons a byte that is 1 or 0.
fn binary(op: BinaryOp, l: Val, r: Val) -> Result<Val, Why> {
    let bits = l.bits.max(r.bits);
    let signed = l.signed && r.signed;
    let (Some(a), Some(b)) = (l.cast(bits, l.signed).value, r.cast(bits, r.signed).value) else {
        let out_bits = if matches!(
            op,
            BinaryOp::Equal
                | BinaryOp::NotEqual
                | BinaryOp::Less
                | BinaryOp::LessEqual
                | BinaryOp::Greater
                | BinaryOp::GreaterEqual
                | BinaryOp::LogicalAnd
                | BinaryOp::LogicalOr
        ) {
            8
        } else {
            bits
        };
        return Ok(Val::unknown(out_bits, signed));
    };
    let (sa, sb) = (sign_extend(a, bits), sign_extend(b, bits));
    let truth = |holds: bool| Val::known(u64::from(holds), 8, false);
    Ok(match op {
        BinaryOp::Add => Val::known(a.wrapping_add(b), bits, signed),
        BinaryOp::Sub => Val::known(a.wrapping_sub(b), bits, signed),
        BinaryOp::Mul => Val::known(a.wrapping_mul(b), bits, signed),
        BinaryOp::Div => {
            if b == 0 {
                return Err(Why("a division by zero".to_string()));
            }
            if signed {
                Val::known(sa.wrapping_div(sb) as u64, bits, signed)
            } else {
                Val::known(a / b, bits, signed)
            }
        }
        BinaryOp::Mod => {
            if b == 0 {
                return Err(Why("a division by zero".to_string()));
            }
            if signed {
                Val::known(sa.wrapping_rem(sb) as u64, bits, signed)
            } else {
                Val::known(a % b, bits, signed)
            }
        }
        BinaryOp::And => Val::known(a & b, bits, signed),
        BinaryOp::Or => Val::known(a | b, bits, signed),
        BinaryOp::Xor => Val::known(a ^ b, bits, signed),
        BinaryOp::Shl => Val::known(a.checked_shl(b as u32).unwrap_or(0), bits, signed),
        BinaryOp::Shr => {
            if l.signed {
                Val::known(
                    sa.checked_shr(b as u32)
                        .unwrap_or(if sa < 0 { -1 } else { 0 }) as u64,
                    bits,
                    signed,
                )
            } else {
                Val::known(a.checked_shr(b as u32).unwrap_or(0), bits, signed)
            }
        }
        BinaryOp::Equal => truth(a == b),
        BinaryOp::NotEqual => truth(a != b),
        BinaryOp::Less => truth(if signed { sa < sb } else { a < b }),
        BinaryOp::LessEqual => truth(if signed { sa <= sb } else { a <= b }),
        BinaryOp::Greater => truth(if signed { sa > sb } else { a > b }),
        BinaryOp::GreaterEqual => truth(if signed { sa >= sb } else { a >= b }),
        BinaryOp::LogicalAnd => truth(a != 0 && b != 0),
        BinaryOp::LogicalOr => truth(a != 0 || b != 0),
    })
}

fn one_line(node: &AstNode) -> String {
    crate::emit::emit_node(node)
        .trim_end()
        .trim_end_matches(';')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lift::{LiftedFunction, Statement, StatementKind, Variable};
    use crate::structure::Analysis;
    use std::collections::BTreeMap as Map;

    struct Nowhere;

    impl World for Nowhere {
        fn read(&self, _address: u64, _len: usize) -> Option<Vec<u8>> {
            None
        }
        fn address_of(&self, _name: &str) -> Option<u64> {
            None
        }
    }

    fn statement(node: AstNode, address: u64) -> Statement {
        Statement {
            node,
            addresses: vec![address],
            kind: StatementKind::Plain,
        }
    }

    fn var(name: &str) -> AstNode {
        AstNode::var(name)
    }

    fn assign(name: &str, rhs: AstNode) -> AstNode {
        AstNode::Assign {
            lhs: Box::new(var(name)),
            rhs: Box::new(rhs),
        }
    }

    /// `sum_to(a)`: a counted loop, as the lifter builds it.
    fn sum_to() -> Stages {
        let nodes = vec![
            Node {
                address: 0x10,
                statements: vec![
                    statement(assign("total", AstNode::constant(0, 8)), 0x10),
                    statement(assign("i", AstNode::constant(1, 4)), 0x14),
                ],
                terminator: Terminator::Goto {
                    target: 1,
                    addresses: Vec::new(),
                },
            },
            Node {
                address: 0x20,
                statements: Vec::new(),
                terminator: Terminator::Branch {
                    cond: AstNode::binary(var("i"), BinaryOp::LessEqual, var("a")),
                    taken: 2,
                    next: 3,
                    addresses: vec![0x20],
                },
            },
            Node {
                address: 0x30,
                statements: vec![
                    statement(
                        assign(
                            "total",
                            AstNode::binary(
                                var("total"),
                                BinaryOp::Add,
                                AstNode::Cast {
                                    ty: "long".to_string(),
                                    target: Box::new(var("i")),
                                },
                            ),
                        ),
                        0x30,
                    ),
                    statement(
                        assign(
                            "i",
                            AstNode::binary(var("i"), BinaryOp::Add, AstNode::constant(1, 4)),
                        ),
                        0x34,
                    ),
                ],
                terminator: Terminator::Goto {
                    target: 1,
                    addresses: Vec::new(),
                },
            },
            Node {
                address: 0x40,
                statements: vec![statement(
                    AstNode::Return {
                        value: Some(Box::new(var("total"))),
                    },
                    0x40,
                )],
                terminator: Terminator::Return,
            },
        ];
        Stages {
            chains: Vec::new(),
            low: Vec::new(),
            medium: nodes,
            high: Vec::new(),
            function: LiftedFunction {
                name: "sum_to".to_string(),
                address: 0x10,
                return_type: "long".to_string(),
                params: vec![Variable {
                    ty: "int".to_string(),
                    name: "a".to_string(),
                }],
                locals: vec![
                    Variable {
                        ty: "long".to_string(),
                        name: "total".to_string(),
                    },
                    Variable {
                        ty: "int".to_string(),
                        name: "i".to_string(),
                    },
                ],
                body: Vec::new(),
                frame: Vec::new(),
                thunk: None,
                return_reason: None,
            },
            analysis: Analysis::default(),
            medium_analysis: Analysis::default(),
            stack_pointer: Map::new(),
            types: Map::new(),
        }
    }

    #[test]
    fn a_counted_loop_runs_to_its_sum() {
        let run = super::run(&sum_to(), &[5], &Nowhere, &Limits::default());
        assert_eq!(run.returned().and_then(|v| v.value), Some(15));
        assert_eq!(run.stop, Stop::Returned(Some(Val::known(15, 64, true))));
        assert_eq!(run.variables["i"].value, Some(6));
        assert_eq!(run.variables["a"].value, Some(5));
        // Two statements to set up, two per round for five rounds, the return.
        assert_eq!(run.steps.len(), 2 + 10 + 1);
        assert_eq!(
            run.steps[0].wrote.as_ref().map(|(name, _)| name.as_str()),
            Some("total")
        );
        let text = run.text();
        assert!(text.contains("; returned 15 (0xf)"), "{text}");
        assert!(text.contains("00000034  i = i + 1  ; i = 2"), "{text}");
        // A step limit stops the run and says so.
        let run = super::run(
            &sum_to(),
            &[1_000_000],
            &Nowhere,
            &Limits {
                steps: 50,
                depth: 1,
            },
        );
        assert_eq!(run.stop, Stop::Steps(50));
        assert!(run.returned().is_none());
        // A parameter not given is unknown, and the branch on it stops the run.
        let run = super::run(&sum_to(), &[], &Nowhere, &Limits::default());
        assert!(
            matches!(&run.stop, Stop::Unknown { at: Some(0x20), what } if what.contains("depends on an unknown value")),
            "{:?}",
            run.stop
        );
    }

    #[test]
    fn values_have_widths_and_signs() {
        assert_eq!(type_of("unsigned int"), (32, false));
        assert_eq!(type_of("char"), (8, true));
        assert_eq!(type_of("int *"), (64, false));
        let minus_one = Val::known(0xffff_ffff, 32, true);
        assert_eq!(minus_one.as_i64(), Some(-1));
        assert_eq!(minus_one.cast(64, true).value, Some(u64::MAX));
        // As C has it: a signed value widens with its sign whatever it is
        // cast to; an unsigned one with zeros.
        assert_eq!(minus_one.cast(64, false).value, Some(u64::MAX));
        assert_eq!(
            Val::known(0xffff_ffff, 32, false).cast(64, false).value,
            Some(0xffff_ffff)
        );
        assert_eq!(minus_one.text(), "-1 (0xffffffff)");
        let less = binary(BinaryOp::Less, minus_one, Val::known(1, 32, true)).unwrap();
        assert_eq!(less.value, Some(1), "signed: -1 < 1");
        let less = binary(
            BinaryOp::Less,
            Val::known(0xffff_ffff, 32, false),
            Val::known(1, 32, false),
        )
        .unwrap();
        assert_eq!(less.value, Some(0), "unsigned: 0xffffffff is not below 1");
        assert!(binary(
            BinaryOp::Div,
            Val::known(1, 32, true),
            Val::known(0, 32, true)
        )
        .is_err());
        let unknown = binary(
            BinaryOp::Add,
            Val::unknown(32, true),
            Val::known(1, 32, true),
        )
        .unwrap();
        assert_eq!(unknown.value, None);
        assert_eq!(
            Val::known(300, 8, false).value,
            Some(44),
            "masked to the width"
        );
    }

    #[test]
    fn memory_is_the_images_until_written() {
        struct Bytes;
        impl World for Bytes {
            fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
                (0x4000..0x4010).contains(&address).then(|| {
                    (0..len)
                        .map(|i| (address as u8).wrapping_add(i as u8))
                        .collect()
                })
            }
            fn address_of(&self, name: &str) -> Option<u64> {
                (name == "counter").then_some(0x4008)
            }
            fn size_of(&self, _name: &str) -> Option<u64> {
                Some(4)
            }
        }
        let load = AstNode::Deref {
            target: Box::new(AstNode::Cast {
                ty: "int *".to_string(),
                target: Box::new(AstNode::constant(0x4000, 8)),
            }),
        };
        let nodes = vec![Node {
            address: 0x10,
            statements: vec![
                statement(assign("x", load.clone()), 0x10),
                statement(
                    assign(
                        "counter",
                        AstNode::binary(var("counter"), BinaryOp::Add, AstNode::constant(1, 4)),
                    ),
                    0x14,
                ),
                statement(
                    AstNode::Assign {
                        lhs: Box::new(load.clone()),
                        rhs: Box::new(AstNode::constant(7, 4)),
                    },
                    0x18,
                ),
                statement(assign("y", load), 0x1c),
                statement(
                    AstNode::Return {
                        value: Some(Box::new(AstNode::binary(var("x"), BinaryOp::Add, var("y")))),
                    },
                    0x20,
                ),
            ],
            terminator: Terminator::Return,
        }];
        let mut stages = sum_to();
        stages.medium = nodes;
        stages.function.params.clear();
        stages.function.locals = vec![
            Variable {
                ty: "int".to_string(),
                name: "x".to_string(),
            },
            Variable {
                ty: "int".to_string(),
                name: "y".to_string(),
            },
        ];
        let run = super::run(&stages, &[], &Bytes, &Limits::default());
        // x is the image's 00 01 02 03; counter (08 09 0a 0b) plus one is written
        // to memory; the store of 7 is read back.
        assert_eq!(run.variables["x"].value, Some(0x0302_0100));
        assert_eq!(run.memory.get(&0x4008), Some(&0x09));
        assert_eq!(run.variables["y"].value, Some(7));
        assert_eq!(run.returned().and_then(|v| v.value), Some(0x0302_0107));
        assert!(run.steps[2]
            .note
            .as_deref()
            .is_some_and(|n| n.contains("wrote 7 at 0x4000")));
    }
}
