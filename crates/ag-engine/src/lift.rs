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
//!   overwrite of a slot makes its value unknown. A slot inside a variable
//!   the analyst made in the frame is always a variable, and the slots
//!   inside one read as parts of it ([`crate::stack_vars`]).
//! * **The state is split at a branch and merged at a join.** Each successor
//!   starts from a copy of the state its predecessor ended in. Where paths
//!   join, a register or slot that holds the same expression on every path
//!   stays that expression; a slot that differs becomes a variable, assigned
//!   on each path by the stores already there; a register that differs
//!   becomes a declared variable named after the register (`eax`), assigned
//!   at the end of each path; a register one path never wrote, or whose value
//!   a call clobbered, becomes unknown, and is refused only if it is read.
//!   A condition the path computed before that assignment reads the variable
//!   — `(edi - 1) != 0` after `edi = edi - 1` is `edi != 0` — unless the
//!   operand is a constant at the compare, an address or a literal, which
//!   keeps its expression: `&completed.0 != &completed.0`, never `rax !=
//!   rax`. A relation with the same expression on both sides is folded to
//!   the constant it is, printed as `if (0) { // constant: &completed.0 !=
//!   &completed.0` (the `constant-conditions` option). A stack pointer that
//!   differs between paths is refused. A loop header is
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
//! * **`ret`** returns `rax`, or nothing — decided from use, not presence
//!   (the `return-liveness` option). When the image knows the function's
//!   callers ([`Symbols::result_uses`]), what they do with `rax` after the
//!   call decides: a caller that reads `eax`/`rax` before writing it — a
//!   store, a compare, a move into another register, an argument — makes
//!   the function return a value at the width of the widest read, and
//!   callers that all write or ignore it make it `void`; a caller that
//!   carries it untouched to its own `ret` passes the question to its
//!   callers. With no caller in the image, a value at a `ret` counts only
//!   if the function wrote `rax` itself on that path: a callee's result
//!   left untouched in `rax`, read by nothing else in the function, is dead,
//!   and that path returns nothing — unless another path returns a value of
//!   the function's own, in which case the leftover path hands on the
//!   callee's result. The live decisions of every `ret` must then agree. The decision is recorded in the function's leading comment
//!   — `// void: no caller reads the result`, `// returns int: main reads
//!   eax after the call` — and in [`LiftedFunction::return_reason`]. Under
//!   `return-liveness presence`, `rax` written on the way to a `ret` is
//!   returned at the width of its last write, whatever reads it.
//! * **A `jmp` out of the function is a tail call.** A node whose last
//!   instruction is a `jmp` to another function — direct, or through a GOT
//!   slot the image resolves to an import ([`Pointee::Import`]), or through
//!   a register that holds such a function — with the stack pointer back at
//!   its entry value is lifted as the `call` and the `ret` it stands for:
//!   `return callee(args);`, the arguments from the register state exactly
//!   as a call's, the result `long` since nothing reads it narrower. A
//!   function that is only the jump, behind at most `endbr64` and `nop`s —
//!   a PLT stub, a forwarding stub — is a *thunk*: it has no body of its
//!   own, and prints as the one line `// thunk for callee`. A `jmp` whose
//!   target is inside the function is an edge of the graph as before, and a
//!   load from a GOT slot is the import's name, since the slot holds its
//!   address. The `tail-calls` option refuses the jump instead.
//!
//! # The judgment calls
//!
//! Where the lifter could reasonably go either way — which argument
//! registers are parameters, how a merged register and a stack slot are
//! named, whether a load from named data is the name or a cast, the order
//! of the operands of `b + a`, whether an unsigned comparison is cast,
//! whether a `cmp` no branch reads is dropped, the calling convention,
//! whether a return value is decided from its use or its presence — the
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
//! 32-bit or 16-bit code; irreducible control flow; a node that ends in a
//! trap; a `jmp` to an address outside the function that names no function
//! (`jumps to 0x…`), or through a register or memory that holds no function
//! the lifter can name (`an indirect jump at 0x…`), or with the stack not
//! back at its entry value; any mnemonic outside `mov`, `movsx`, `movsxd`,
//! `movzx`, `cdqe`, `add`, `sub`, `and`, `or`, `xor`, `inc`, `dec`, `imul`,
//! `lea`, `push`, `pop`, `leave`, `call`, `ret`, `cmp`, `test`, `jmp`, the
//! conditional jumps, `nop` and `endbr64`; an indirect call; a branch whose
//! flags are not tracked; a stack the lifter loses track of or that differs
//! between paths; `ret`s that disagree; and a value that reaches a
//! statement without being known — a register read before it is written
//! that is not an argument register, one clobbered by a call, one that
//! two paths left different and the lifter could not name, or a callee's
//! result on one path and nothing on another, which is dead at a `ret`
//! but refused if read.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use iced_x86::Mnemonic;

use crate::arch::Bitness;
use crate::ast::{AstNode, BinaryOp, StructField};
use crate::cfg::{JumpTable, ProcedureCfg};
use crate::cfgwalk::{never_returns_by_name, resolve_branches_among, Entries};
use crate::cpu_context::{DecodedInsn, Flow, Operand, RC_GPR, RC_IP, RC_NONE};
use crate::liveness::{rax_name, CallSiteUse, ResultUse};
use crate::options::{
    Builtins, DeadCompares, IndirectCalls, MergedNames, OperandOrder, Options, Parameters,
    PointerLoads, ReturnLiveness, SlotNames, StructInitializers, TailCalls, UnsignedCompare,
};
use crate::pipeline::Disasm;
use crate::register::RegisterId;
use crate::structure::{self, Analysis, Node, Terminator};

/// What the lifter asks the image: the name of a function it calls, what a
/// pointer it takes lands on, and what the callers of the function being
/// lifted do with its result.
///
/// A plain function from an address to a function name is a `Symbols` that
/// knows no data and no callers, which is what the tests of the lifter use.
pub trait Symbols {
    /// The name of the function at `address`, when it has one.
    fn function_name(&self, address: u64) -> Option<String>;

    /// The analyst's word at `address` on the judgment calls made there
    /// ([`crate::options::SiteOverride`]); nothing said unless the analyst
    /// did.
    fn site(&self, _address: u64) -> crate::options::SiteOverride {
        crate::options::SiteOverride::default()
    }

    /// Whether a call to the function at `address` comes back: not for
    /// `exit`, `abort` and their kind, nor for a function whose every path
    /// ends in one. Every call returns unless the image says otherwise.
    fn returns(&self, _address: u64) -> bool {
        true
    }

    /// The conditions under which the function at `address` does not
    /// return — an exit-on-error helper's — each over the names of its
    /// parameters, in order, so that a caller can say them of its own
    /// arguments. None unless the image knows.
    fn noreturn_when(&self, _address: u64) -> Vec<(Vec<String>, AstNode)> {
        Vec::new()
    }

    /// The function at `address` as its own lift reads, when the analyst
    /// marked it to be inlined into its callers' pseudocode: `None` when it
    /// is not marked, and why it cannot be had when it is marked and does
    /// not lift — a phrase completing `f is not inlined at 0x401020: …`.
    /// Nothing is inlined unless the image says.
    fn inline_body(&self, _address: u64) -> Option<Result<LiftedFunction, String>> {
        None
    }

    /// The analyst's words on the variables of the function at `address`:
    /// which are merged, where one is split or has a new version, what
    /// values one holds, by the names the lift declares, the variables
    /// made in its stack frame and the types given. None unless the image
    /// says.
    fn variable_edits(&self, _address: u64) -> crate::merge::VariableEdits {
        crate::merge::VariableEdits::default()
    }

    /// The types the analyst defined ([`crate::types`]), which the
    /// variables' types name; `None` for the platform's primitives alone.
    fn types(&self) -> Option<std::sync::Arc<crate::types::TypeStore>> {
        None
    }

    /// What the pointer to `address` lands on, when the image knows.
    fn pointee(&self, _address: u64) -> Option<Pointee> {
        None
    }

    /// What the callers of the function at `address` do with the value it
    /// leaves in `rax`: one entry per call site the image knows, decided by
    /// [`crate::liveness::result_use_after`] over the caller's code. Empty
    /// when the image knows of no caller — or of no call graph at all —
    /// and the lifter falls back to what the function itself does.
    fn result_uses(&self, _address: u64) -> Vec<CallSiteUse> {
        Vec::new()
    }
}

impl<F: Fn(u64) -> Option<String>> Symbols for F {
    fn function_name(&self, address: u64) -> Option<String> {
        self(address)
    }
}

/// The function entries the control-flow walk stops at, read from the
/// lifter's symbols: a function the symbols name, or a GOT slot they say
/// holds an import. This is how [`lift_block`] walks the way an image does.
struct SymbolEntries<'a>(&'a dyn Symbols);

/// The analyst's words on the sites, read through the symbols.
struct SymbolSites<'a>(&'a dyn Symbols);

impl crate::options::Sites for SymbolSites<'_> {
    fn at(&self, address: u64) -> crate::options::SiteOverride {
        self.0.site(address)
    }
}

impl Entries for SymbolEntries<'_> {
    fn is_function(&self, address: u64) -> bool {
        self.0.function_name(address).is_some()
    }

    fn is_import_slot(&self, slot: u64) -> bool {
        matches!(self.0.pointee(slot), Some(Pointee::Import(_)))
    }

    fn table_allowed(&self, site: u64) -> bool {
        self.0.site(site).switch != Some(false)
    }

    fn returns(&self, callee: u64) -> bool {
        self.0.returns(callee)
    }

    fn slot_returns(&self, slot: u64) -> bool {
        !matches!(self.0.pointee(slot), Some(Pointee::Import(name)) if never_returns_by_name(&name))
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
    /// A slot the run-time loader fills with the address of a named function
    /// — a GOT entry — by the function's name. A load from the slot is that
    /// function; a `jmp` through it is a tail call to it.
    Import(String),
    /// A slot that holds the address of an Objective-C selector's name — a
    /// selector reference the runtime fixes up — by the selector. A load
    /// from the slot is the selector, which a message send is sent with.
    Selector(String),
    /// A slot that holds the address of an Objective-C class object — a
    /// class reference — by the class object's name. A load from the slot
    /// is the class, which a class message is sent to.
    ClassRef(String),
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
    pub fn argument_registers(self) -> &'static [u32] {
        match self {
            Abi::SystemV => &[RDI, RSI, RDX, RCX, R8, R9],
            Abi::Win64 => &[RCX, RDX, R8, R9],
        }
    }

    /// Whether a call leaves the register alone.
    pub fn is_callee_saved(self, index: u32) -> bool {
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
    /// Where the variable lives: the register, stack slot or flag the lift
    /// made it from — more than one for a variable another was merged
    /// into, none where the lift does not say.
    pub placements: Vec<Placement>,
}

impl Variable {
    /// A variable of type `ty` named `name`, with no placement.
    pub fn new(ty: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            ty: ty.into(),
            name: name.into(),
            placements: Vec::new(),
        }
    }

    /// The variable, living in `placement`.
    pub fn placed(mut self, placement: Placement) -> Self {
        self.placements.push(placement);
        self
    }
}

/// Where a variable of a lifted function lives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Placement {
    /// A general register at a width: `name` as the width spells it,
    /// `eax`, and `full` the whole register it is part of, `rax`.
    Register { name: String, full: String },
    /// A stack slot: its offset from the stack pointer at the function's
    /// entry, and its size in bytes.
    Stack { offset: i64, size: u32 },
    /// A flag of the flags register, `zf`, `cf`. The x86 lift reads its
    /// flags as conditions and keeps no flag variable; a plugin's lift may.
    Flag(String),
    /// No register or slot of its own: a value the lift saved before what
    /// it was computed from changed.
    Temporary,
    /// A variable of the function `callee`, inlined here: where it lives
    /// in the callee's own frame.
    Inlined {
        callee: String,
        placement: Box<Placement>,
    },
}

impl Placement {
    /// The general register `index` at the width `bits`.
    pub(crate) fn register(index: u32, bits: u32) -> Self {
        Placement::Register {
            name: gpr_name(index, bits),
            full: gpr_name(index, 64),
        }
    }

    /// The placement as the variables listing spells it: `rdi`, `eax (in
    /// rax)`, `[sp-0x14] 4 bytes`, `zf`, `temporary`, and `rdi, inlined
    /// from f` for a callee's.
    pub fn spelled(&self) -> String {
        match self {
            Placement::Register { name, full } if name == full => name.clone(),
            Placement::Register { name, full } => format!("{name} (in {full})"),
            Placement::Stack { offset, size } => {
                let sign = if *offset < 0 { '-' } else { '+' };
                let bytes = if *size == 1 { "byte" } else { "bytes" };
                format!("[sp{sign}{:#x}] {size} {bytes}", offset.unsigned_abs())
            }
            Placement::Flag(name) => name.clone(),
            Placement::Temporary => "temporary".to_string(),
            Placement::Inlined { callee, placement } => {
                format!("{}, inlined from {callee}", placement.spelled())
            }
        }
    }

    /// The placement of a variable of `callee` inlined into a caller.
    pub fn inlined_from(&self, callee: &str) -> Self {
        Placement::Inlined {
            callee: callee.to_string(),
            placement: Box::new(self.clone()),
        }
    }
}

impl std::fmt::Display for Placement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.spelled())
    }
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

/// What is known of a call, for the end of its line: that the callee does
/// not return when the arguments are such.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallNote {
    /// The address of the call instruction.
    pub at: u64,
    /// The callee, by the name the call is printed with.
    pub callee: String,
    /// The note: `checked does not return when a == 0`.
    pub text: String,
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
    /// `switch (index) { case a: case b: { arm } … }`: the node is the
    /// index, and each arm carries the case values that reach it. An arm
    /// that runs on to the statement after the `switch` ends in `break`.
    Switch { arms: Vec<SwitchArm> },
}

/// One arm of a `switch`: the case values that reach it, and its body.
#[derive(Debug, Clone, PartialEq)]
pub struct SwitchArm {
    /// The case values, in table order.
    pub values: Vec<i64>,
    /// The statements of the arm.
    pub body: Vec<Statement>,
    /// The case values as the pseudocode spells them, beside `values`:
    /// an enumerator's name where the index is an enumeration's variable
    /// ([`crate::typed`]). Empty for the numbers.
    pub labels: Vec<String>,
}

impl SwitchArm {
    /// The case values as the pseudocode spells them: the labels when
    /// there is one a value, the numbers otherwise.
    pub fn spelled(&self) -> Vec<String> {
        if self.labels.len() == self.values.len() {
            self.labels.clone()
        } else {
            self.values.iter().map(i64::to_string).collect()
        }
    }
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
            StatementKind::Switch { arms } => arms.iter().map(|arm| &arm.body).collect(),
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
            StatementKind::Switch { arms } => arms.iter_mut().map(|arm| &mut arm.body).collect(),
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
    /// The C return type: `void`, or the type of the width the function
    /// returns at. Decided from use (see the module's `ret` rule);
    /// `return_reason` says what decided it.
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
    /// What is known of the function besides its return: that it does not
    /// return, or does not return under a condition, and where the walk did
    /// not go on and why — printed as comments after the one that says what
    /// decided the return type.
    pub notes: Vec<String>,
    /// What is known of the calls the function makes, by the call's
    /// address: that the callee does not return when the arguments are
    /// such — printed as a comment at the end of the call's line.
    pub call_notes: Vec<CallNote>,
    /// The conditions under which the function does not return, over its
    /// parameters: an `if` whose one arm ends in a call that never returns
    /// while the other goes on. For its callers to say of their arguments.
    pub noreturn_when: Vec<AstNode>,
    /// The function this one is a thunk for, when it is one: a function
    /// that is only a `jmp` to another, behind at most `endbr64` and `nop`s,
    /// such as a PLT stub. A thunk has no body, parameters or return type
    /// of its own — they are the callee's — and prints as the one line
    /// `// thunk for callee`; `frame` holds every instruction.
    pub thunk: Option<String>,
    /// What decided the return type, completing `// void: …` or `// returns
    /// int: …` in the function's leading comment: `no caller reads the
    /// result`, `main reads eax after the call`. `None` for a thunk, whose
    /// return type is its callee's.
    pub return_reason: Option<String>,
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
    lift_inner(
        disasm, cfg, entry, name, bitness, abi, symbols, options, false,
    )
    .map(|stages| stages.function)
}

/// The stages of a lift, kept for the intermediate languages: the chains
/// the function was cut into, the statements over temporaries and slots
/// before they were resolved (the low level), the nodes over variables
/// (the medium level), the structured body (the high level), and the
/// function the lift ended in.
pub struct Stages {
    /// The chains, the entry's first; the graph the low and medium levels
    /// are laid on.
    pub chains: Vec<StageChain>,
    /// The low-level statements of each chain, in the chains' order.
    pub low: Vec<Vec<LowStatement>>,
    /// The medium-level nodes: one per chain as the lifter built them, or
    /// as a plugin's rewriter left them — more, fewer, or pointed elsewhere.
    pub medium: Vec<Node>,
    /// The structured body.
    pub high: Vec<Statement>,
    /// The function the lift ended in.
    pub function: LiftedFunction,
    /// The analysis of the chain graph — its order, dominators and loops —
    /// which the lifted and low levels lie on.
    pub analysis: Analysis,
    /// The analysis of the medium-level graph, which a plugin's rewriter may
    /// have changed: the same as `analysis` when none did.
    pub medium_analysis: Analysis,
    /// The stack pointer's offset from the entry's before each instruction,
    /// where the lifter knew it.
    pub stack_pointer: BTreeMap<u64, i64>,
    /// The C type of every name the levels use: parameters, locals, slots,
    /// temporaries, the flags.
    pub types: BTreeMap<String, String>,
    /// What the lift saw of the stack frame: the slots the code reads and
    /// writes, the registers it saves, the slots whose address it takes,
    /// the prologue's `sub rsp, N`, and the analyst's variables it made.
    /// Empty for a thunk and a plugin's lift.
    pub slots: crate::frame::SlotFacts,
}

/// One chain of a lift: a run of blocks the lift reads as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageChain {
    /// The address of the first instruction.
    pub address: u64,
    /// The addresses of the instructions, in order.
    pub instructions: Vec<u64>,
    /// The chains this one goes on to, by index.
    pub successors: Vec<usize>,
}

/// One statement of the low level: the lifter's own, over temporaries,
/// stack slots and registers, before the temporaries are resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowStatement {
    pub text: String,
    /// The statement with its casts explicit: every constant with its
    /// width, a value stored at another width cast to it.
    pub casts: String,
    /// What kind of statement it is: `store`, `call`, `assign`, `return`,
    /// `compare`, `branch`, `switch`.
    pub kind: &'static str,
    pub addresses: Vec<u64>,
    /// What the statement writes: a temporary, a slot, a variable, a
    /// register.
    pub defines: Vec<String>,
    /// What it reads.
    pub uses: Vec<String>,
}

/// Lift the function at `entry` and keep every stage. A thunk has one
/// chain and no statements at any level.
#[allow(clippy::too_many_arguments)]
pub fn lift_stages(
    disasm: &Disasm,
    cfg: &ProcedureCfg,
    entry: u64,
    name: &str,
    bitness: Bitness,
    abi: Abi,
    symbols: &dyn Symbols,
    options: &Options,
) -> Result<Stages, NotLifted> {
    lift_inner(
        disasm, cfg, entry, name, bitness, abi, symbols, options, true,
    )
}

/// The stages of a function an architecture lifted itself
/// ([`crate::plugin::Architecture::lift`]): its medium-level graph goes
/// through the registered rewriters and is analyzed and structured as the
/// lifter's own would be. The chains are the function's blocks in `cfg`, by
/// the nodes' addresses, for the lifted level; there is no low level.
pub fn lift_graph(
    graph: crate::plugin::LiftedGraph,
    disasm: &Disasm,
    cfg: &ProcedureCfg,
    address: u64,
    name: &str,
    options: &Options,
) -> Result<Stages, NotLifted> {
    let crate::plugin::LiftedGraph {
        return_type,
        params,
        locals,
        entry,
        nodes,
        frame,
    } = graph;
    if nodes.is_empty() {
        return Err(NotLifted::new("the architecture lifted no blocks"));
    }
    if entry >= nodes.len() {
        return Err(NotLifted::new(format!(
            "the architecture's entry is block {entry} of {}",
            nodes.len()
        )));
    }
    // A function that returns a value returns it in a statement: a block
    // that returns without one would fall off the end of the pseudocode.
    if return_type != "void" {
        for (index, node) in nodes.iter().enumerate() {
            if matches!(node.terminator, Terminator::Return)
                && !matches!(
                    node.statements.last().map(|statement| &statement.node),
                    Some(AstNode::Return { value: Some(_) })
                )
            {
                return Err(NotLifted::new(format!(
                    "block {index} at {:#x} returns no value in a function returning {return_type}",
                    node.address
                )));
            }
        }
    }
    let successors = |nodes: &[Node]| -> Vec<Vec<usize>> {
        nodes
            .iter()
            .map(|node| node.terminator.successors())
            .collect()
    };
    // The chains: one per node, holding the instructions of the block of
    // `cfg` that starts where the node does.
    let stage_chains: Vec<StageChain> = nodes
        .iter()
        .map(|node| {
            let instructions = cfg
                .blocks
                .iter()
                .find(|block| block.from == node.address)
                .or_else(|| cfg.block_containing(node.address))
                .map(|block| {
                    disasm
                        .instructions
                        .iter()
                        .filter(|ins| ins.address >= block.from && ins.address < block.to)
                        .map(|ins| ins.address)
                        .collect()
                })
                .unwrap_or_default();
            StageChain {
                address: node.address,
                instructions,
                successors: node.terminator.successors(),
            }
        })
        .collect();
    let analysis = structure::analyze(&successors(&nodes), entry, |node| nodes[node].address)?;
    let (nodes, rewritten) = crate::plugin::rewrite_nodes(address, name, entry, nodes)?;
    let medium_analysis = if rewritten {
        structure::analyze(&successors(&nodes), entry, |node| nodes[node].address)?
    } else {
        analysis.clone()
    };
    let body = structure::structure(&nodes, &medium_analysis, entry, options, &());
    let mut types: BTreeMap<String, String> = BTreeMap::new();
    for variable in params.iter().chain(&locals) {
        types.insert(variable.name.clone(), variable.ty.clone());
    }
    let function = LiftedFunction {
        name: name.to_string(),
        address,
        return_type,
        params,
        locals,
        body: body.clone(),
        frame,
        thunk: None,
        notes: Vec::new(),
        call_notes: Vec::new(),
        noreturn_when: Vec::new(),
        return_reason: None,
    };
    Ok(Stages {
        chains: stage_chains,
        low: Vec::new(),
        medium: nodes,
        high: body,
        function,
        analysis,
        medium_analysis,
        stack_pointer: BTreeMap::new(),
        types,
        slots: crate::frame::SlotFacts::default(),
    })
}

/// The lift; the stages are kept when `keep`, and empty otherwise, so the
/// pseudocode's path pays for none of their text and copies.
#[allow(clippy::too_many_arguments)]
fn lift_inner(
    disasm: &Disasm,
    cfg: &ProcedureCfg,
    entry: u64,
    name: &str,
    bitness: Bitness,
    abi: Abi,
    symbols: &dyn Symbols,
    options: &Options,
    keep: bool,
) -> Result<Stages, NotLifted> {
    if bitness != Bitness::Bits64 {
        return Err(NotLifted::new(format!("{bitness} code")));
    }
    let chains = chains(disasm, cfg, entry, symbols)?;
    let successors: Vec<Vec<usize>> = chains.iter().map(|chain| chain.end.successors()).collect();
    let stage_chains: Vec<StageChain> = chains
        .iter()
        .zip(&successors)
        .map(|(chain, successors)| StageChain {
            address: chain.address,
            instructions: chain.instructions.iter().map(|ins| ins.address).collect(),
            successors: successors.clone(),
        })
        .collect();
    let mut lifter = Lifter::new(abi, symbols, *options);
    // The analyst's words on the function's variables; the variables made
    // in its frame are read by the walk itself.
    let edits = symbols.variable_edits(entry);
    let store = symbols.types().unwrap_or_else(|| {
        std::sync::Arc::new(crate::types::TypeStore::new(
            crate::types::DataModel::of_abi(abi),
        ))
    });
    let (made, refused) =
        crate::stack_vars::accept(&edits.stack_vars, options.stack_slot_names, &store);
    lifter.covered = made.clone();
    if let Some(callee) = lifter.thunk(&chains)? {
        let function = LiftedFunction {
            name: name.to_string(),
            address: entry,
            return_type: "void".to_string(),
            params: Vec::new(),
            locals: Vec::new(),
            body: Vec::new(),
            frame: chains[0]
                .instructions
                .iter()
                .map(|ins| ins.address)
                .collect(),
            thunk: Some(callee),
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            return_reason: None,
        };
        let analysis = structure::analyze(&successors, 0, |node| chains[node].address)?;
        return Ok(Stages {
            chains: stage_chains,
            low: Vec::new(),
            medium: Vec::new(),
            high: Vec::new(),
            function,
            medium_analysis: analysis.clone(),
            analysis,
            stack_pointer: BTreeMap::new(),
            types: BTreeMap::new(),
            slots: crate::frame::SlotFacts::default(),
        });
    }
    let analysis = structure::analyze(&successors, 0, |node| chains[node].address)?;
    let lifted = lifter.lift_chains(&chains, &analysis)?;
    let low: Vec<Vec<LowStatement>> = if keep {
        let names = LowNames {
            temps: &lifter.temps,
            slots: options.stack_slot_names,
        };
        lifted
            .iter()
            .map(|(statements, terminator)| {
                let mut rows: Vec<LowStatement> = statements
                    .iter()
                    .map(|statement| statement.low(&names))
                    .collect();
                if let Some(end) = low_terminator(terminator) {
                    rows.push(end);
                }
                rows
            })
            .collect()
    } else {
        Vec::new()
    };
    // The slots the chains store to, with their widths, for the types.
    let stored: Vec<(i64, u32)> = if keep {
        lifted
            .iter()
            .flat_map(|(statements, _)| statements)
            .filter_map(|statement| match statement {
                Stmt::Store { offset, bits, .. } => Some((*offset, *bits)),
                _ => None,
            })
            .collect()
    } else {
        Vec::new()
    };
    lifter.decide_return(entry, &lifted)?;
    let nodes = lifter.resolve_all(&chains, lifted)?;
    // The plugins' rewriters have the graph before it is structured. The
    // graph they leave is analyzed again whenever one ran — a rewriter may
    // edit the nodes directly — while the chains keep their own analysis
    // for the lifted and low levels.
    let (nodes, rewritten) = crate::plugin::rewrite_nodes(entry, name, 0, nodes)?;
    let medium_analysis = if rewritten {
        let successors: Vec<Vec<usize>> = nodes
            .iter()
            .map(|node| node.terminator.successors())
            .collect();
        structure::analyze(&successors, 0, |node| nodes[node].address)?
    } else {
        analysis.clone()
    };
    let medium = if keep { nodes.clone() } else { Vec::new() };
    let body = structure::structure(&nodes, &medium_analysis, 0, options, &SymbolSites(symbols));
    let stack_pointer = if keep {
        std::mem::take(&mut lifter.stack_pointers)
    } else {
        BTreeMap::new()
    };
    let mut types: BTreeMap<String, String> = BTreeMap::new();
    if keep {
        for (offset, bits) in &lifter.locals {
            types.insert(
                local_name(options.stack_slot_names, *offset),
                type_name(*bits).to_string(),
            );
        }
        for temp in &lifter.temps {
            types.insert(
                temp.name.clone(),
                type_name(temp.bits.unwrap_or(64)).to_string(),
            );
        }
        for saved in &lifter.saved {
            types.insert(saved.name.clone(), saved.ty.clone());
        }
        // A slot that never became a variable is typed by its stores.
        for (offset, bits) in stored {
            types
                .entry(local_name(options.stack_slot_names, offset))
                .or_insert_with(|| type_name(bits).to_string());
        }
        types.insert("flags".to_string(), "flags".to_string());
    }
    let call_sites = std::mem::take(&mut lifter.call_sites);
    let mut slots = std::mem::take(&mut lifter.slot_facts);
    slots.address_taken = lifter.address_taken.clone();
    let mut function = lifter.finish(name, entry, &chains, body)?;
    // The analyst's variables in the frame, read over the lift's locals
    // inside them before anything keys on their names.
    function.notes.extend(refused);
    slots.made = crate::stack_vars::make(&mut function, &made, &store);
    // The types the analyst gave the lift's variables, by their lift names.
    crate::typed::apply_var_types(&mut function, &edits.var_types, &store, &slots.made);
    // The calls to the functions the analyst marked are read as their
    // bodies, once the function's own return and notes are decided.
    crate::inline::inline_calls(&mut function, symbols, &call_sites);
    // The analyst's splits, versions, pinned values and merges, on the body
    // as it then reads; a value at a table's jump narrows its cases from
    // the table's first.
    let tables: BTreeMap<u64, i64> = cfg
        .jump_tables
        .iter()
        .map(|table| (table.site, table.base))
        .collect();
    crate::merge::apply_edits_with(&mut function, &edits, &SymbolSites(symbols), &tables);
    // The members, elements and enumerators the types make of the body.
    crate::typed::read_types(&mut function, &store);
    let high = if keep {
        function.body.clone()
    } else {
        Vec::new()
    };
    // Where the walk did not go on, and why.
    for halt in &cfg.halts {
        function.notes.push(format!(
            "analysis halted at {:#x}: {}",
            halt.target,
            halt.why.text()
        ));
    }
    if keep {
        for variable in function.params.iter().chain(&function.locals) {
            types.insert(variable.name.clone(), variable.ty.clone());
        }
    }
    Ok(Stages {
        chains: if keep { stage_chains } else { Vec::new() },
        low,
        medium,
        high,
        function,
        analysis,
        medium_analysis,
        stack_pointer,
        types,
        slots,
    })
}

/// A chain's end as a low-level statement, when it says more than the
/// graph does: the condition branched on, the index switched on.
fn low_terminator(terminator: &Terminator) -> Option<LowStatement> {
    match terminator {
        Terminator::Branch {
            cond, addresses, ..
        } => Some(LowStatement {
            text: format!("branch if {}", one_line(&crate::emit::emit_node(cond))),
            casts: format!(
                "branch if {}",
                one_line(&crate::emit::emit_node(&crate::il::with_casts(cond)))
            ),
            kind: "branch",
            addresses: addresses.clone(),
            defines: Vec::new(),
            uses: crate::il::names_in(cond),
        }),
        Terminator::Switch {
            index, addresses, ..
        } => Some(LowStatement {
            text: format!("switch on {}", one_line(&crate::emit::emit_node(index))),
            casts: format!(
                "switch on {}",
                one_line(&crate::emit::emit_node(&crate::il::with_casts(index)))
            ),
            kind: "switch",
            addresses: addresses.clone(),
            defines: Vec::new(),
            uses: crate::il::names_in(index),
        }),
        Terminator::Return | Terminator::Goto { .. } => None,
    }
}

/// Emitted text as one line, the newline the emitter ends with dropped.
fn one_line(text: &str) -> String {
    text.trim_end().trim_end_matches(';').to_string()
}

/// The names the low level spells its values by: a stack slot by the
/// variable the slot resolves to, a call's result by the temporary's
/// variable — the names the expressions the lifter has already built read
/// them by, so a read at the low level finds its write.
struct LowNames<'a> {
    temps: &'a [Temp],
    slots: SlotNames,
}

impl LowNames<'_> {
    fn slot(&self, offset: i64) -> String {
        local_name(self.slots, offset)
    }

    fn temp(&self, index: usize) -> String {
        self.temps
            .get(index)
            .map(|temp| temp.name.clone())
            .unwrap_or_else(|| format!("t{index}"))
    }
}

impl Sym {
    /// The symbolic value's text, and the name it reads when it is one
    /// thing read.
    fn low_text(&self, names: &LowNames, casts: bool) -> (String, Vec<String>) {
        match self {
            Sym::Node(node) if casts => (
                one_line(&crate::emit::emit_node(&crate::il::with_casts(node))),
                crate::il::names_in(node),
            ),
            Sym::Node(node) => (
                one_line(&crate::emit::emit_node(node)),
                crate::il::names_in(node),
            ),
            Sym::Stack(offset) => {
                // The address of a slot: no version of its value is read.
                (format!("&{}", names.slot(*offset)), Vec::new())
            }
            Sym::Entry(index) => {
                // The value a register held when the function was entered.
                let name = format!("entry{index}");
                (name.clone(), vec![name])
            }
            Sym::Temp(index) => {
                let name = names.temp(*index);
                (name.clone(), vec![name])
            }
            Sym::Dead(reason) => (format!("dead /* {reason} */"), Vec::new()),
            Sym::Unknown(reason) => (format!("unknown /* {reason} */"), Vec::new()),
        }
    }
}

impl Value {
    fn low_text(&self, names: &LowNames, casts: bool) -> (String, Vec<String>) {
        self.sym.low_text(names, casts)
    }
}

impl Stmt {
    /// The statement at the low level.
    fn low(&self, names: &LowNames) -> LowStatement {
        match self {
            Stmt::Call {
                temp,
                node,
                addresses,
            } => {
                let temp = names.temp(*temp);
                LowStatement {
                    text: format!("{temp} = {}", one_line(&crate::emit::emit_node(node))),
                    casts: format!(
                        "{temp} = {}",
                        one_line(&crate::emit::emit_node(&crate::il::with_casts(node)))
                    ),
                    kind: "call",
                    addresses: addresses.clone(),
                    defines: vec![temp],
                    uses: crate::il::names_in(node),
                }
            }
            Stmt::Store {
                offset,
                bits,
                value,
                addresses,
            } => {
                let (text, uses) = value.low_text(names, false);
                let slot = names.slot(*offset);
                // A value stored at another width than it has is cast to it,
                // whole.
                let cast_text = if value.bits != *bits {
                    match &value.sym {
                        Sym::Node(node) => one_line(&crate::emit::emit_node(&crate::il::cast_to(
                            type_name(*bits),
                            node,
                        ))),
                        _ => format!("({}){}", type_name(*bits), value.low_text(names, true).0),
                    }
                } else {
                    value.low_text(names, true).0
                };
                LowStatement {
                    text: format!("{slot}:{bits} = {text}"),
                    casts: format!("{slot}:{bits} = {cast_text}"),
                    kind: "store",
                    addresses: addresses.clone(),
                    defines: vec![slot],
                    uses,
                }
            }
            Stmt::Assign {
                lhs,
                value,
                addresses,
            } => {
                let (text, uses) = value.low_text(names, false);
                let (cast_text, _) = value.low_text(names, true);
                let defines = match lhs {
                    AstNode::Var { .. } | AstNode::Register { .. } => crate::il::names_in(lhs),
                    _ => Vec::new(),
                };
                // A store through a pointer reads what the pointer is made of.
                let mut uses = uses;
                if defines.is_empty() {
                    uses.extend(crate::il::names_in(lhs));
                }
                let left = one_line(&crate::emit::emit_node(lhs));
                LowStatement {
                    text: format!("{left} = {text}"),
                    casts: format!("{left} = {cast_text}"),
                    kind: "assign",
                    addresses: addresses.clone(),
                    defines,
                    uses,
                }
            }
            Stmt::Return {
                value,
                leftover,
                addresses,
            } => {
                let (text, casts, uses) = match value {
                    Some(value) => {
                        let (text, uses) = value.low_text(names, false);
                        let (cast_text, _) = value.low_text(names, true);
                        (
                            format!("return {text}"),
                            format!("return {cast_text}"),
                            uses,
                        )
                    }
                    None => match leftover {
                        Some(temp) => {
                            let temp = names.temp(*temp);
                            let text = format!("return /* {temp} left in rax */");
                            (text.clone(), text, vec![temp])
                        }
                        None => ("return".to_string(), "return".to_string(), Vec::new()),
                    },
                };
                LowStatement {
                    text,
                    casts,
                    kind: "return",
                    addresses: addresses.clone(),
                    defines: Vec::new(),
                    uses,
                }
            }
            Stmt::Compare {
                name,
                lhs,
                rhs,
                addresses,
            } => {
                let (left, mut uses) = lhs.low_text(names, false);
                let (right, more) = rhs.low_text(names, false);
                let (left_cast, _) = lhs.low_text(names, true);
                let (right_cast, _) = rhs.low_text(names, true);
                uses.extend(more);
                LowStatement {
                    text: format!("flags = {name}({left}, {right})"),
                    casts: format!("flags = {name}({left_cast}, {right_cast})"),
                    kind: "compare",
                    addresses: addresses.clone(),
                    defines: vec!["flags".to_string()],
                    uses,
                }
            }
            Stmt::Builtin {
                name,
                args,
                addresses,
            } => {
                let mut uses = Vec::new();
                let mut texts = Vec::new();
                let mut casts = Vec::new();
                for arg in args {
                    let (text, more) = arg.low_text(names, false);
                    let (cast, _) = arg.low_text(names, true);
                    uses.extend(more);
                    texts.push(text);
                    casts.push(cast);
                }
                // The registers the instruction leaves changed.
                let defines = if *name == "__builtin_memcpy" {
                    vec!["rdi".to_string(), "rsi".to_string(), "rcx".to_string()]
                } else {
                    vec!["rdi".to_string(), "rcx".to_string()]
                };
                LowStatement {
                    text: format!("{name}({})", texts.join(", ")),
                    casts: format!("{name}({})", casts.join(", ")),
                    kind: "call",
                    addresses: addresses.clone(),
                    defines,
                    uses,
                }
            }
        }
    }
}

/// Lift a run of instructions as a function entered at `entry`: the graph
/// is built from the instructions alone, stopping at a `jmp` to a function
/// `symbols` names, as an image's walk does.
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
    let cfg = resolve_branches_among(&disasm, entry, &SymbolEntries(symbols));
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
    /// In a `jmp` that leaves the function: to another function by address,
    /// or through a register or memory. A tail call when it is lifted, or
    /// refused there.
    Leave,
    /// In a `jcc`: to `taken` when it holds, else into `next`.
    Branch { taken: usize, next: usize },
    /// By falling into the chain, which other blocks also reach.
    Fall(usize),
    /// In a `jmp` through a jump table: to each case's chain by the value
    /// of the index register the table records.
    Switch {
        table: JumpTable,
        cases: Vec<(Vec<i64>, usize)>,
    },
    /// In a call to a function that never returns: the walk gave the
    /// block no successor, and nothing follows the call — not even the
    /// next function's entry, when the call is the last instruction
    /// before it: the walk keeps a function from running into the next.
    NoReturn,
    /// Where the walk did not go on: a side of a branch it did not follow
    /// to `target`, from the instruction at `site` — the analyst said not
    /// to, or the target does not decode. A chain of no instructions is
    /// the side itself, standing in for the code that is not analyzed; a
    /// chain of instructions ends in a jump the walk did not follow, or in
    /// an instruction it did not go on from.
    Halted { site: u64, target: u64 },
}

impl End {
    fn successors(&self) -> Vec<usize> {
        match self {
            End::Return | End::Leave | End::NoReturn | End::Halted { .. } => Vec::new(),
            End::Jump(target) | End::Fall(target) => vec![*target],
            End::Branch { taken, next } => vec![*taken, *next],
            End::Switch { cases, .. } => {
                let mut nodes = Vec::new();
                for (_, node) in cases {
                    if !nodes.contains(node) {
                        nodes.push(*node);
                    }
                }
                nodes
            }
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
/// `ret` or in a `jmp` that leaves the function — one to a function
/// `symbols` names (a walk told the image's entries stops there too; one
/// told nothing follows it into the callee, which this does not), or an
/// indirect one; a chain that ends in a trap is refused as `the block ends
/// in <mnemonic>`. A side of a branch the walk halted at is a chain of its
/// own, after the others, with no instructions: it says the code there is
/// not analyzed, and goes nowhere.
fn chains(
    disasm: &Disasm,
    cfg: &ProcedureCfg,
    entry: u64,
    symbols: &dyn Symbols,
) -> Result<Vec<Chain>, NotLifted> {
    let block_at = |address: u64| cfg.blocks.iter().find(|block| block.from == address);
    // A `jmp` to the entry of another function leaves this one: a tail call.
    // A `jmp` through a jump table the walk resolved stays in the function:
    // it is the function's own `switch`.
    let table_at = |site: u64| cfg.jump_tables.iter().find(|table| table.site == site);
    // A branch the walk recorded as a tail call leaves too, whatever the
    // image names at its target: under `branches-end-procedures` that is a
    // jump into another routine's body.
    let tail_call_at = |site: u64| cfg.tail_calls.iter().any(|tail| tail.site == site);
    let leaves = |ins: &DecodedInsn| match ins.flow {
        Flow::UnconditionalBranch(target) => {
            target != entry
                && (symbols.function_name(target).is_some() || tail_call_at(ins.address))
        }
        Flow::IndirectBranch => table_at(ins.address).is_none(),
        // A fall into the next function, which the walk made a tail call.
        Flow::Next => tail_call_at(ins.address),
        _ => false,
    };
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
        let last_leaves = instructions.last().is_some_and(leaves);
        if !last_leaves {
            for &successor in &block.successor_addresses {
                if seen.insert(successor) {
                    starts.push(successor);
                }
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
    // The halted sides, each a chain after the others, by site and target.
    let halted = |site: u64, target: u64| {
        cfg.halts
            .iter()
            .any(|halt| halt.site == site && halt.target == target)
    };
    let mut sides: Vec<(u64, u64)> = Vec::new();
    let mut side_at = |site: u64, target: u64| {
        let position = sides
            .iter()
            .position(|side| *side == (site, target))
            .unwrap_or_else(|| {
                sides.push((site, target));
                sides.len() - 1
            });
        index.len() + position
    };
    let mut out = Vec::with_capacity(raw.len());
    for (address, instructions, successors) in raw {
        let Some(last) = instructions.last() else {
            return Err(NotLifted::new(format!("no code at {address:#x}")));
        };
        let site = last.address;
        let after = last.address + last.length as u64;
        let mut go = |target: u64| {
            if halted(site, target) {
                Ok(side_at(site, target))
            } else {
                node_at(target)
            }
        };
        let end = match last.flow {
            Flow::Return => End::Return,
            _ if leaves(last) => End::Leave,
            Flow::IndirectBranch => {
                let table = table_at(last.address)
                    .expect("an indirect jump that does not leave reads a table")
                    .clone();
                let mut cases = Vec::new();
                for (values, target) in table.cases() {
                    cases.push((values, go(target)?));
                }
                End::Switch { table, cases }
            }
            Flow::UnconditionalBranch(target) if halted(site, target) => {
                End::Halted { site, target }
            }
            Flow::UnconditionalBranch(target) => End::Jump(node_at(target)?),
            // A conditional branch that leaves the function has no
            // chain to go to on the taken side, and the lifter has no
            // statement for "return a call, or go on": refused by name.
            Flow::ConditionalBranch(target) if tail_call_at(last.address) => {
                return Err(NotLifted::new(format!(
                    "a conditional branch leaves the function for {target:#x} at {:#x}",
                    last.address
                )))
            }
            Flow::ConditionalBranch(target) if target == after => End::Jump(go(after)?),
            Flow::ConditionalBranch(target) => End::Branch {
                taken: go(target)?,
                next: go(after)?,
            },
            Flow::Call(_) | Flow::IndirectCall if successors.is_empty() => End::NoReturn,
            // An instruction the walk did not go on from.
            _ if successors.is_empty() && halted(site, after) => End::Halted {
                site,
                target: after,
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
        out.push(Chain {
            address,
            instructions,
            end,
        });
    }
    out.extend(sides.into_iter().map(|(site, target)| Chain {
        address: target,
        instructions: Vec::new(),
        end: End::Halted { site, target },
    }));
    Ok(out)
}

/// The expression `node` without the `- offset` the compiler put on a
/// switch's index to bring its first case to zero, when that subtraction is
/// there to be seen through the casts around it: `(unsigned)(a - 3)` with an
/// offset of 3 is `(unsigned)a`. `None` when the offset is zero or the shape
/// is not that.
fn without_offset(node: &AstNode, offset: i64) -> Option<AstNode> {
    if offset == 0 {
        return None;
    }
    match node {
        AstNode::Cast { ty, target } => Some(AstNode::Cast {
            ty: ty.clone(),
            target: Box::new(without_offset(target, offset)?),
        }),
        AstNode::Binary {
            lhs,
            op: BinaryOp::Sub,
            rhs,
        } => match rhs.as_ref() {
            AstNode::Constant { value, .. } if *value as i64 == offset => Some((**lhs).clone()),
            _ => None,
        },
        AstNode::Binary {
            lhs,
            op: BinaryOp::Add,
            rhs,
        } => match rhs.as_ref() {
            AstNode::Constant { value, width_bytes }
                if offset < 0 && (*value as i64) == -offset
                    || (*width_bytes < 8
                        && (*value as i64 - (1i64 << (*width_bytes * 8))) == -offset) =>
            {
                Some((**lhs).clone())
            }
            _ => None,
        },
        _ => None,
    }
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
    /// A callee's result, untouched, on the paths into a join that had the
    /// register, and nothing on the others: no value of the function's own,
    /// by the callee's name. Refused if read; dead at a `ret`.
    Dead(String),
    /// Not tracked, and why.
    Unknown(String),
}

/// The conditions under which a function does not return: at the top of
/// its body, an `if` whose one arm ends in a call to a function that never
/// returns while the other goes on, by the condition — negated when it is
/// the `else` that ends so. Only a condition over the parameters and the
/// globals is one: a condition on a `local`, one of `locals`, means
/// nothing to a caller. Deeper `if`s are left out, since their conditions
/// hold only under the ones above them; and so is every `if` after a
/// statement that may return, jump, loop or write a parameter, since what
/// its condition says of the parameters is not what held at entry.
fn noreturn_conditions(statements: &[Statement], locals: &[String]) -> Vec<AstNode> {
    let mut conditions = Vec::new();
    for statement in statements {
        if let StatementKind::If {
            then_part,
            else_part,
        } = &statement.kind
        {
            let then_ends = ends_without_return(then_part);
            let else_ends = ends_without_return(else_part);
            let condition = match (then_ends, else_ends) {
                (true, false) => Some(statement.node.clone()),
                (false, true) => Some(statement.node.negated()),
                _ => None,
            };
            if let Some(condition) = condition {
                let on_a_local = condition
                    .any(&|node| matches!(node, AstNode::Var { name } if locals.contains(name)));
                if !on_a_local {
                    conditions.push(condition);
                }
            }
        }
        if !holds_after(statement, locals) {
            break;
        }
    }
    conditions
}

/// Whether what held of the parameters before `statement` holds after
/// it, whichever way it went: not past a loop or a `switch`, a `return`,
/// a `goto` or a label at any depth, nor a store to a variable that is
/// not one of `locals` — a parameter, or a global a condition may read.
fn holds_after(statement: &Statement, locals: &[String]) -> bool {
    if !matches!(
        statement.kind,
        StatementKind::Plain | StatementKind::If { .. }
    ) {
        return false;
    }
    !any_statement(std::slice::from_ref(statement), &|inner| {
        inner.node.any(&|node| match node {
            AstNode::Return { .. }
            | AstNode::Goto { .. }
            | AstNode::Label { .. }
            | AstNode::IfGoto { .. }
            | AstNode::Loop { .. }
            | AstNode::Break
            | AstNode::Continue => true,
            AstNode::Assign { lhs, .. } => {
                !matches!(lhs.as_ref(), AstNode::Var { name } if locals.contains(name))
            }
            _ => false,
        })
    })
}

/// Whether `statements` end in a call to a function that never returns.
fn ends_without_return(statements: &[Statement]) -> bool {
    matches!(
        statements.last(),
        Some(Statement {
            kind: StatementKind::Plain,
            node: AstNode::Intrinsic { name, .. },
            ..
        }) if name == UNREACHABLE
    )
}

/// The statement that marks the end of a path after a call that never
/// returns: `__builtin_unreachable()`, as the compilers name it.
pub const UNREACHABLE: &str = "__builtin_unreachable";

/// The statement that marks where the walk did not go on — a side of a
/// branch the analyst said not to follow, or one whose target does not
/// decode — with the target's address as its one argument. The path ends
/// there, as it does after [`UNREACHABLE`]; the pseudocode says the code
/// at the target is not analyzed, and the transpiler traps.
pub const HALTED: &str = "__analysis_halted";

/// The target of a statement that is [`HALTED`], when it is one.
pub fn halted_target(node: &AstNode) -> Option<u64> {
    match node {
        AstNode::Intrinsic { name, args } if name == HALTED => match args.as_slice() {
            [AstNode::Constant { value, .. }] => Some(*value),
            _ => None,
        },
        _ => None,
    }
}

/// Whether any statement, at any depth, satisfies `pred`.
fn any_statement(statements: &[Statement], pred: &dyn Fn(&Statement) -> bool) -> bool {
    statements.iter().any(|statement| {
        pred(statement)
            || match &statement.kind {
                StatementKind::Plain => false,
                StatementKind::If {
                    then_part,
                    else_part,
                } => any_statement(then_part, pred) || any_statement(else_part, pred),
                StatementKind::While { body }
                | StatementKind::DoWhile { body }
                | StatementKind::For { body, .. } => any_statement(body, pred),
                StatementKind::Switch { arms } => {
                    arms.iter().any(|arm| any_statement(&arm.body, pred))
                }
            }
    })
}

/// What a call or a jump calls.
#[derive(Debug, Clone, PartialEq)]
enum Callee {
    /// A function by name, at an address.
    Named(String, u64),
    /// An expression the call goes through: a parameter, a loaded field.
    Through(AstNode),
}

impl Callee {
    /// The callee as a reason names it.
    fn label(&self) -> String {
        match self {
            Callee::Named(name, _) => name.clone(),
            Callee::Through(expression) => one_line_of(expression),
        }
    }
}

/// How a callee is reached: by a `call`, by a `jmp` that leaves the
/// function, or through the control-flow guard's dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum How {
    Call,
    Jump,
    Dispatch,
}

/// The control-flow guard's pointers a Windows image calls through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guard {
    /// `__guard_dispatch_icall_fptr`: the call goes to the function in `rax`.
    Dispatch,
    /// `__guard_check_icall_fptr`: `rcx` is validated, and the call returns.
    Check,
}

/// An expression on one line, as the pseudocode spells it.
fn one_line_of(node: &AstNode) -> String {
    crate::emit::emit_node(node)
        .trim_end()
        .trim_end_matches(';')
        .to_string()
}

/// Why a [`Sym::Dead`] value cannot be read.
fn dead_reason(callee: &str) -> String {
    format!("{callee}'s result on one path and nothing on another")
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
            (Sym::Dead(x), Sym::Dead(y)) => x == y,
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

/// What set a flag: the kind of write, and the operands it was written
/// from, so a consumer can read the flag back as a relation.
#[derive(Debug, Clone)]
enum Producer {
    /// `cmp lhs, rhs`: every flag of `lhs - rhs`.
    Cmp(Value, Value),
    /// `test lhs, rhs`: the flags of `lhs & rhs`, the carry clear.
    Test(Value, Value),
    /// An arithmetic instruction with its operands and its result: the
    /// zero and sign flags from the result, the carry from the operation —
    /// a borrow for `sub`, a carry out for `add`, none for the logical
    /// operations.
    Arith {
        op: BinaryOp,
        lhs: Value,
        rhs: Value,
        result: Value,
        /// Whether the source operand is the destination too (`add eax,
        /// eax`), so neither operand's value stands after the write.
        same: bool,
    },
    /// An instruction known only by its result: the zero and sign flags.
    Result(Value),
    /// `bt value, index`: the carry is the bit.
    Bit(Value, Value),
}

/// The flags one instruction wrote: what set them, at what width, where,
/// and which of the flags it wrote.
#[derive(Debug, Clone)]
struct Flags {
    producer: Producer,
    bits: u32,
    /// The producing instruction.
    at: u64,
    /// Its mnemonic, for the refusal.
    mnemonic: String,
    /// The flags it wrote, as the decoder's bits.
    written: u32,
}

/// The six status flags, as the decoder's bits.
const CF: u32 = iced_x86::RflagsBits::CF;
const PF: u32 = iced_x86::RflagsBits::PF;
const AF: u32 = iced_x86::RflagsBits::AF;
const ZF: u32 = iced_x86::RflagsBits::ZF;
const SF: u32 = iced_x86::RflagsBits::SF;
const OF: u32 = iced_x86::RflagsBits::OF;
const STATUS_FLAGS: u32 = CF | PF | AF | ZF | SF | OF;

/// A flag's name, for a refusal.
fn flag_name(bit: u32) -> &'static str {
    match bit {
        CF => "CF",
        PF => "PF",
        AF => "AF",
        ZF => "ZF",
        SF => "SF",
        OF => "OF",
        _ => "a flag",
    }
}

/// The flags of the machine as the lifter tracks them: each status flag
/// with the instruction that wrote it last, when one tracked did. An
/// instruction that writes some flags and not others — `inc`, which leaves
/// the carry — leaves the others' producers standing, so a consumer that
/// reads flags two instructions wrote is told so.
#[derive(Debug, Clone, Default)]
struct FlagState {
    by_flag: BTreeMap<u32, Flags>,
}

impl FlagState {
    fn clear(&mut self) {
        self.by_flag.clear();
    }

    /// Record `flags` as the producer of every flag it wrote.
    fn set(&mut self, flags: Flags) {
        for bit in [CF, PF, AF, ZF, SF, OF] {
            if flags.written & bit != 0 {
                self.by_flag.insert(bit, flags.clone());
            }
        }
    }

    /// Drop the flags whose producer `reads` tells of.
    fn retain(&mut self, mut keep: impl FnMut(&Flags) -> bool) {
        self.by_flag.retain(|_, flags| keep(flags));
    }

    /// The one producer of the flags in `needed`, or why there is none:
    /// a flag nothing tracked wrote, or flags two instructions wrote.
    fn producer_of(&self, needed: u32, consumer: &str, at: u64) -> Result<Flags, NotLifted> {
        let mut found: Option<&Flags> = None;
        for bit in [CF, PF, AF, ZF, SF, OF] {
            if needed & bit == 0 {
                continue;
            }
            let Some(flags) = self.by_flag.get(&bit) else {
                return Err(NotLifted::new(format!(
                    "the {consumer} at {at:#x} reads {} that nothing tracked set",
                    flag_name(bit)
                )));
            };
            match found {
                None => found = Some(flags),
                Some(first) if first.at != flags.at => {
                    return Err(NotLifted::new(format!(
                        "the {consumer} at {at:#x} reads flags two instructions set: the {} at {:#x} and the {} at {:#x}",
                        first.mnemonic, first.at, flags.mnemonic, flags.at
                    )));
                }
                Some(_) => {}
            }
        }
        found
            .cloned()
            .ok_or_else(|| NotLifted::new(format!("the {consumer} at {at:#x} reads no flag")))
    }

    /// The flags every state agrees on: the same instruction wrote each.
    fn merged(states: &[&FlagState]) -> FlagState {
        let mut out = FlagState::default();
        let Some(first) = states.first() else {
            return out;
        };
        for (bit, flags) in &first.by_flag {
            if states.iter().all(|state| {
                state
                    .by_flag
                    .get(bit)
                    .is_some_and(|other| other.at == flags.at)
            }) {
                out.by_flag.insert(*bit, flags.clone());
            }
        }
        out
    }
}

/// The symbolic machine state at one point of the function.
#[derive(Debug, Clone)]
struct State {
    /// What each general register holds, by GPR index.
    regs: BTreeMap<u32, Value>,
    /// The stack slots, by offset from the entry stack pointer.
    stack: BTreeMap<i64, Slot>,
    /// What set each flag, if anything tracked did.
    flags: FlagState,
}

impl State {
    /// The state at entry: the stack pointer is the entry stack pointer.
    fn initial() -> Self {
        let mut regs = BTreeMap::new();
        regs.insert(RSP, Value::new(Sym::Stack(0), 64, Vec::new()));
        Self {
            regs,
            stack: BTreeMap::new(),
            flags: FlagState::default(),
        }
    }

    fn empty() -> Self {
        Self {
            regs: BTreeMap::new(),
            stack: BTreeMap::new(),
            flags: FlagState::default(),
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
    /// A callee's result, untouched, on the paths that have the register,
    /// and nothing on the others: no value of the function's own.
    Dead(String),
    /// Different, and not something a variable could hold.
    Unknown { reason: String, bits: u32 },
}

/// A call result, named `v1`, `v2`… once it is used.
#[derive(Debug, Clone)]
struct Temp {
    name: String,
    /// The width the result is read at; `None` until it is read.
    bits: Option<u32>,
    /// The callee whose result it is.
    callee: String,
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
    /// The return. `leftover` is the call result that `rax` holds exactly
    /// as the call left it, when it does: the value is then a callee's, not
    /// the function's own, and whether it is returned is decided by
    /// [`Lifter::decide_return`].
    Return {
        value: Option<Value>,
        leftover: Option<usize>,
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
    /// A memory operation an instruction does whole — `rep movsb` is
    /// `__builtin_memcpy(rdi, rsi, rcx)` — as the call it stands for.
    Builtin {
        name: &'static str,
        args: Vec<Value>,
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
    /// What is known of the calls made so far: the call's address, the
    /// callee's name and the condition under which it does not return,
    /// over this function's own values — a call result inlined later is
    /// inlined here too.
    call_notes: Vec<(u64, String, AstNode)>,
    /// The direct calls made so far: the call's address, and the callee's —
    /// for the calls the analyst has inlined.
    call_sites: BTreeMap<u64, u64>,
    /// While resolving: the variable the last constant store wrote to or
    /// into, and the offset just past that store — where the next word of a
    /// string put on the stack would go.
    string_run: Option<(i64, i64)>,
    /// The slots that are variables, with their width.
    locals: BTreeMap<i64, u32>,
    /// The stack pointer's offset from the entry's before each instruction,
    /// where it is known, for the levels.
    stack_pointers: BTreeMap<u64, i64>,
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
    /// The width the function returns at, once decided; `None` for `void`.
    return_bits: Option<u32>,
    /// What decided it.
    return_reason: String,
    /// The temporaries declared, once the statements are resolved.
    declared: Vec<Variable>,
    /// The analyst's variables in the frame: every slot starting inside one
    /// is a variable, its stores kept and its loads read from memory.
    covered: Vec<crate::stack_vars::Made>,
    /// What the walk saw of the frame, for its layout.
    slot_facts: crate::frame::SlotFacts,
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
            call_notes: Vec::new(),
            call_sites: BTreeMap::new(),
            string_run: None,
            locals: BTreeMap::new(),
            stack_pointers: BTreeMap::new(),
            params: BTreeMap::new(),
            temps: Vec::new(),
            saved: Vec::new(),
            merged: BTreeMap::new(),
            globals: BTreeSet::new(),
            statements: Vec::new(),
            return_bits: None,
            return_reason: String::new(),
            declared: Vec::new(),
            covered: Vec::new(),
            slot_facts: crate::frame::SlotFacts::default(),
        }
    }

    /// Whether the slot at `offset` starts inside a variable the analyst
    /// made.
    fn is_covered(&self, offset: i64) -> bool {
        self.covered.iter().any(|made| made.holds(offset))
    }

    /// Forget what one pass over the function found, keeping what holds
    /// across passes: the slots whose address is taken, and the names of
    /// the registers that became variables.
    fn reset(&mut self) {
        self.state = State::initial();
        self.stack_pointers.clear();
        self.locals.clear();
        self.params.clear();
        self.temps.clear();
        self.saved.clear();
        self.globals.clear();
        self.statements.clear();
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
                    if let Terminator::Branch { cond, .. } = &mut terminator {
                        // A condition computed before the path assigned a
                        // variable reads the variable: `(edi - 1) != 0`
                        // after `edi = edi - 1` is `edi != 0`. An operand
                        // that is a constant at the compare — an address
                        // such as `&completed.0`, held in `rdi` as well as
                        // in the `rax` the join is about to name — keeps
                        // its expression: the variable's name would say
                        // `rax != rax` for a comparison the bytes made
                        // between two addresses.
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
                                if !expression.is_constant() {
                                    *cond = cond.clone().replace(expression, lhs);
                                }
                            }
                        }
                        // A relation with the same expression on both
                        // sides is the constant it is, and remembers the
                        // comparison for the reader.
                        *cond = std::mem::replace(cond, AstNode::ConditionTrue).folded();
                    }
                    statements.extend(appended);
                    (statements, terminator)
                })
                .collect());
        }
        Err(NotLifted::new("the loops do not settle"))
    }

    /// Mark the end of a path where the walk did not go on from `site` to
    /// `target`.
    fn halted(&mut self, site: u64, target: u64) {
        self.statements.push(Stmt::Builtin {
            name: HALTED,
            args: vec![Value::node(AstNode::constant(target, 8), 64, vec![site])],
            addresses: vec![site],
        });
    }

    /// Lift one chain from the current state, and say how it leaves.
    fn lift_chain(&mut self, chain: &Chain) -> Result<Terminator, NotLifted> {
        self.pending_compare = None;
        // A side the walk did not follow: the marker says the code there
        // is not analyzed, and the path ends with it.
        if let (End::Halted { site, target }, []) = (&chain.end, chain.instructions.as_slice()) {
            self.halted(*site, *target);
            return Ok(Terminator::Return);
        }
        let (last, body) = chain
            .instructions
            .split_last()
            .expect("a chain has an instruction");
        for ins in body {
            self.step(ins)?;
        }
        // The chain's last instruction is stepped by some ends and not
        // others; the stack pointer before it is noted either way.
        self.note_stack_pointer(last.address);
        match chain.end {
            End::Return => {
                self.step(last)?;
                Ok(Terminator::Return)
            }
            // The call is made, and the path ends there without a `return`
            // of its own: the callee never comes back.
            End::NoReturn => {
                self.step(last)?;
                // The marker says the path ends here: the structurer reads
                // it as no fall-through, the emitter prints nothing for it,
                // and the transpiler writes it for the compiler.
                self.statements.push(Stmt::Builtin {
                    name: UNREACHABLE,
                    args: Vec::new(),
                    addresses: vec![last.address],
                });
                Ok(Terminator::Return)
            }
            End::Leave => {
                self.tail_jump(last)?;
                Ok(Terminator::Return)
            }
            // A jump the walk did not follow does nothing of its own; an
            // instruction it did not go on from is made, and the path ends
            // after it.
            End::Halted { site, target } => {
                if !branches(last) {
                    self.step(last)?;
                }
                self.halted(site, target);
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
            End::Switch {
                ref table,
                ref cases,
            } => {
                // The index is what the register the table is read by
                // holds at the jump: the `switch`'s own expression.
                let Some(register) = table.index else {
                    return Err(NotLifted::new(format!(
                        "the jump table at {:#x} names no index register",
                        last.address
                    )));
                };
                let value = self.read(register, last.address)?;
                let index = self.node_of(&value)?;
                let mut addresses = vec![last.address];
                addresses.extend(value.from.iter().copied());
                // The case values the table records are the source's, but
                // the register was read after the `sub` that brought the
                // first case to zero, so the index says `a - 3` where the
                // cases say 3, 4, 5. Where the subtraction is there to be
                // seen, the index is read without it and the cases stand
                // as the source wrote them; otherwise the cases come down
                // to meet the index.
                let (index, cases) = match without_offset(&index, table.base) {
                    Some(index) => (index, cases.clone()),
                    None => (
                        index,
                        cases
                            .iter()
                            .map(|(values, node)| {
                                (values.iter().map(|v| v - table.base).collect(), *node)
                            })
                            .collect(),
                    ),
                };
                Ok(Terminator::Switch {
                    index,
                    cases,
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
                Resolution::Dead(callee) => {
                    let Key::Reg(index) = key else {
                        unreachable!("only a register holds a call result");
                    };
                    out.regs
                        .insert(index, Value::new(Sym::Dead(callee), 64, Vec::new()));
                }
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

        // A flag survives a join only when every path had the same
        // instruction write it.
        let flag_states: Vec<&FlagState> = states.iter().map(|state| &state.flags).collect();
        out.flags = FlagState::merged(&flag_states);
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
                // A callee's result exactly as the call left it on the paths
                // that have the register, and nothing on the others: no
                // value of the function's own reaches the join. The common
                // shape is `if (c) f(); return;`.
                if !all_present {
                    let leftover = |value: &Value| match &value.sym {
                        Sym::Temp(temp) if value.from.len() == 1 => {
                            Some(self.temps[*temp].callee.clone())
                        }
                        Sym::Dead(callee) => Some(callee.clone()),
                        _ => None,
                    };
                    if let Some(callee) = present.first().and_then(|value| leftover(value)) {
                        if present.iter().all(|value| leftover(value).is_some()) {
                            return Ok(Resolution::Dead(callee));
                        }
                    }
                }
                // An argument register a path never wrote still holds its
                // parameter there — and it is a parameter only if the merge
                // reads it, which an unknown merge never does: a register a
                // call clobbered on one path is unknown after the join, not
                // the parameter the other path never touched.
                let known = all_present || self.abi.argument_registers().contains(&index);
                if known && expressions && agree {
                    if !all_present {
                        self.parameter_of(index, bits);
                    }
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
                Resolution::Dead(callee) => forced.push((
                    key,
                    Forced::Unknown {
                        reason: dead_reason(&callee),
                        bits: 64,
                    },
                )),
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
            Sym::Dead(callee) => return Ok(Value::unknown(dead_reason(&callee), bits)),
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
        self.slot_facts.accesses.insert((offset, bits / 8, at));
        if let Some(slot) = self.state.stack.get(&offset) {
            if slot.bits == bits {
                return slot.value.clone().also_from(at);
            }
        }
        // Inside an analyst's variable every store is kept, so the memory
        // holds what was written in parts.
        if self.state.overlaps(offset, bits) && !self.is_covered(offset) {
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
        self.slot_facts.accesses.insert((offset, bits / 8, at));
        if let Sym::Entry(index) = value.sym {
            self.slot_facts.saved.insert(offset, gpr_name(index, 64));
        }
        self.kill(offset, bits);
        if self.is_covered(offset) {
            self.locals.entry(offset).or_insert(bits);
        }
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
            // A read of an analyst's variable reads memory, not this
            // store: two paths that store to it stay the one variable at a
            // join, and a read past the join comes from its own
            // instruction alone.
            let from = if self.is_covered(offset) {
                Vec::new()
            } else {
                vec![at]
            };
            self.state.stack.insert(
                offset,
                Slot {
                    bits,
                    value: Value::node(AstNode::var(name), bits, from),
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
            self.saved.push(
                Variable::new(type_name(slot.bits), temp.clone()).placed(Placement::Temporary),
            );
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
        // A flag whose producer read the variable is stale now.
        self.state.flags.retain(|flags| {
            let reads = |value: &Value| value.reads_var(name);
            !match &flags.producer {
                Producer::Cmp(lhs, rhs) | Producer::Test(lhs, rhs) | Producer::Bit(lhs, rhs) => {
                    reads(lhs) || reads(rhs)
                }
                Producer::Arith {
                    lhs, rhs, result, ..
                } => reads(lhs) || reads(rhs) || reads(result),
                Producer::Result(value) => reads(value),
            }
        });
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
        let covered: Vec<i64> = self
            .state
            .stack
            .keys()
            .copied()
            .filter(|&offset| self.is_covered(offset))
            .collect();
        for offset in self.address_taken.iter().copied().chain(covered) {
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
        let covered = &self.covered;
        for (&offset, slot) in self.state.stack.iter_mut() {
            if self.address_taken.contains(&offset) || covered.iter().any(|m| m.holds(offset)) {
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
            Sym::Unknown(_) | Sym::Dead(_) | Sym::Stack(_) | Sym::Entry(_) => return Ok(None),
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
        // A GOT slot holds the address of the import it is relocated to, so
        // a pointer-wide load from it is that function; a selector
        // reference holds the address of the selector's name, so a load
        // from it is the selector.
        if let Sym::Node(AstNode::Constant { value: slot, .. }) = &address.sym {
            if bits == 64 {
                match self.symbols.pointee(*slot) {
                    Some(Pointee::Import(name)) => {
                        return Ok(Value::node(
                            AstNode::FunctionName {
                                name,
                                address: *slot,
                            },
                            bits,
                            from,
                        ));
                    }
                    Some(Pointee::Selector(text)) => {
                        return Ok(Value::node(AstNode::StringLiteral { text }, bits, from));
                    }
                    Some(Pointee::ClassRef(name)) => {
                        self.globals.insert(name.clone());
                        return Ok(Value::node(AstNode::var(name), bits, from));
                    }
                    _ => {}
                }
            }
        }
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
            Sym::Dead(callee) => Err(NotLifted::new(dead_reason(callee))),
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
        // The decoder says which flags the instruction writes; one that says
        // nothing is taken to write them all.
        let written = if ins.flags_written & STATUS_FLAGS == 0 {
            STATUS_FLAGS
        } else {
            ins.flags_written & STATUS_FLAGS
        };
        self.state.flags.set(Flags {
            producer,
            bits,
            at: ins.address,
            mnemonic: mnemonic_name(ins),
            written,
        });
    }

    // ---- instructions -----------------------------------------------------

    /// Note the stack pointer's offset from the entry's, as it stands
    /// before the instruction at `address`, when it is known.
    fn note_stack_pointer(&mut self, address: u64) {
        if let Some(Sym::Stack(offset)) = self.state.regs.get(&RSP).map(|value| &value.sym) {
            self.stack_pointers.insert(address, *offset);
        }
    }

    fn step(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        self.note_stack_pointer(ins.address);
        let mnemonic = Mnemonic::try_from(ins.mnemonic as usize).unwrap_or(Mnemonic::INVALID);
        // The first `sub rsp, N` the walk meets — the entry's chain comes
        // first — is the prologue's, and N the frame's size.
        if mnemonic == Mnemonic::Sub && self.slot_facts.frame_size.is_none() {
            if let [Operand::Register(reg), Operand::Imm(n)] = ins.operands.as_slice() {
                if reg.class == RC_GPR && reg.index == RSP && reg.bit_size == 64 && *n > 0 {
                    self.slot_facts.frame_size = u64::try_from(*n).ok();
                }
            }
        }
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
            Mnemonic::Neg => self.neg(ins),
            Mnemonic::Bt => self.bt(ins),
            Mnemonic::Adc => self.carry_op(BinaryOp::Add, ins),
            Mnemonic::Sbb => self.carry_op(BinaryOp::Sub, ins),
            Mnemonic::Lea => self.lea(ins),
            Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq => {
                self.string_op(false, ins)
            }
            Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => {
                self.string_op(true, ins)
            }
            Mnemonic::Push => self.push(ins),
            Mnemonic::Pop => self.pop(ins),
            Mnemonic::Leave => self.leave(ins),
            Mnemonic::Call => self.call(ins),
            Mnemonic::Ret => self.ret(ins),
            // The conditional families, by the condition code in the name.
            _ if cc_of(mnemonic, "set").is_some() => {
                let cc = cc_of(mnemonic, "set").expect("checked");
                self.setcc(cc, ins)
            }
            _ if cc_of(mnemonic, "cmov").is_some() => {
                let cc = cc_of(mnemonic, "cmov").expect("checked");
                self.cmovcc(cc, ins)
            }
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
            // The flags of `0 ^ 0`: zero set, carry clear.
            self.set_flags(
                Producer::Arith {
                    op: BinaryOp::Xor,
                    lhs: zero.clone(),
                    rhs: zero.clone(),
                    result: zero.clone(),
                    same: true,
                },
                bits,
                ins,
            );
            return self.assign(dest, bits, zero, ins);
        }
        let lhs = self.value_of(dest, bits, ins)?;
        let rhs = self.value_of(src, bits, ins)?;
        let result = self.arith(op, lhs.clone(), rhs.clone(), bits, ins.address)?;
        self.set_flags(
            Producer::Arith {
                op,
                lhs,
                rhs,
                result: result.clone(),
                same: dest == src,
            },
            bits,
            ins,
        );
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
        let result = self.arith(op, lhs.clone(), one.clone(), bits, ins.address)?;
        self.set_flags(
            Producer::Arith {
                op,
                lhs,
                rhs: one,
                result: result.clone(),
                same: false,
            },
            bits,
            ins,
        );
        self.assign(dest, bits, result, ins)
    }

    /// `neg dest`: zero minus the operand, the flags of the subtraction.
    fn neg(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let [dest] = ins.operands.as_slice() else {
            return Err(NotLifted::new("neg with no operand"));
        };
        let bits = width_of(dest).ok_or_else(|| NotLifted::new("neg with no width"))?;
        let value = self.value_of(dest, bits, ins)?;
        let zero = Value::node(constant(0, bits), bits, vec![ins.address]);
        let result = self.arith(
            BinaryOp::Sub,
            zero.clone(),
            value.clone(),
            bits,
            ins.address,
        )?;
        self.set_flags(
            Producer::Arith {
                op: BinaryOp::Sub,
                lhs: zero,
                rhs: value,
                result: result.clone(),
                same: true,
            },
            bits,
            ins,
        );
        self.assign(dest, bits, result, ins)
    }

    /// `bt value, index`: the carry is the bit; nothing is written.
    fn bt(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let (dest, src, bits) = self.two(ins)?;
        let value = self.value_of(dest, bits, ins)?.also_from(ins.address);
        let index = self.value_of(src, bits, ins)?.also_from(ins.address);
        self.set_flags(Producer::Bit(value, index), bits, ins);
        Ok(())
    }

    /// `setcc dest`: the condition as the byte it is, 1 or 0.
    fn setcc(&mut self, cc: Cc, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let [dest] = ins.operands.as_slice() else {
            return Err(NotLifted::new(format!(
                "{} with no operand",
                mnemonic_name(ins)
            )));
        };
        let (cond, addresses) = self.condition_of(cc, ins)?;
        // `xor eax, eax; setl al`: the byte lands in a register known to be
        // zero, so the whole register is the condition, zero-extended — the
        // idiom that spares a `movzx`.
        let mut bits = 8;
        if let Operand::Register(reg) = dest {
            if reg.bit_size == 8 && reg.bit_offset == 0 {
                if let Ok(index) = self.gpr(*reg) {
                    if let Some(current) = self.state.regs.get(&index) {
                        if current.bits >= 32
                            && matches!(&current.sym, Sym::Node(AstNode::Constant { value: 0, .. }))
                        {
                            bits = current.bits;
                        }
                    }
                }
            }
        }
        self.assign(dest, bits, Value::node(cond, bits, addresses), ins)
    }

    /// `cmovcc dest, src`: the source when the condition holds, else the
    /// destination as it was.
    fn cmovcc(&mut self, cc: Cc, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let (dest, src, bits) = self.two(ins)?;
        let (cond, mut addresses) = self.condition_of(cc, ins)?;
        let then = self.value_of(src, bits, ins)?;
        let otherwise = self.value_of(dest, bits, ins)?;
        addresses.extend(then.from.iter().chain(&otherwise.from).copied());
        let node = AstNode::Ternary {
            cond: Box::new(cond),
            then: Box::new(self.node_of(&then)?),
            otherwise: Box::new(self.node_of(&otherwise)?),
        };
        self.assign(dest, bits, Value::node(node, bits, sorted(addresses)), ins)
    }

    /// `adc dest, src` and `sbb dest, src`: the operation with the carry
    /// added or borrowed, the carry read from what set it. `sbb r, r` is the
    /// idiom for zero minus the carry.
    fn carry_op(&mut self, op: BinaryOp, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let (dest, src, bits) = self.two(ins)?;
        let carry = self.carry(ins, bits)?;
        let lhs = self.value_of(dest, bits, ins)?;
        let rhs = self.value_of(src, bits, ins)?;
        let at = ins.address;
        let result = if op == BinaryOp::Sub && dest == src {
            let zero = Value::node(constant(0, bits), bits, vec![at]);
            self.arith(BinaryOp::Sub, zero, carry, bits, at)?
        } else {
            let partial = self.arith(op, lhs, rhs, bits, at)?;
            self.arith(op, partial, carry, bits, at)?
        };
        self.set_flags(Producer::Result(result.clone()), bits, ins);
        self.assign(dest, bits, result, ins)
    }

    /// The carry flag as a value, read back from what set it: a borrow
    /// after a compare or a subtraction, a carry out after an addition,
    /// clear after a logical operation, the bit after `bt`.
    fn carry(&mut self, ins: &DecodedInsn, bits: u32) -> Result<Value, NotLifted> {
        let flags = self
            .state
            .flags
            .producer_of(CF, &mnemonic_name(ins), ins.address)?;
        // The compare has a consumer now: the statement kept for it goes.
        if let Some((produced, index)) = self.pending_compare {
            if produced == flags.at && index < self.statements.len() {
                self.statements.remove(index);
            }
            self.pending_compare = None;
        }
        let compared = flags.bits;
        let mut from = vec![flags.at];
        let unsigned_less = |lifter: &mut Self,
                             l: &Value,
                             r: &Value|
         -> Result<AstNode, NotLifted> {
            let (l, r) = (lifter.node_of(l)?, lifter.node_of(r)?);
            Ok(match lifter.options.unsigned_compare {
                UnsignedCompare::Cast => {
                    AstNode::binary(unsigned(l, compared), BinaryOp::Less, unsigned(r, compared))
                }
                UnsignedCompare::Bare => AstNode::binary(l, BinaryOp::Less, r),
            })
        };
        let node = match &flags.producer {
            Producer::Cmp(lhs, rhs) => {
                from.extend(lhs.from.iter().chain(&rhs.from).copied());
                unsigned_less(self, lhs, rhs)?
            }
            // `neg`: a borrow unless the operand was zero, which its result says.
            Producer::Arith {
                op: BinaryOp::Sub,
                lhs,
                result,
                ..
            } if matches!(&lhs.sym, Sym::Node(AstNode::Constant { value: 0, .. })) => {
                from.extend(result.from.iter().copied());
                AstNode::binary(
                    self.node_of(result)?,
                    BinaryOp::NotEqual,
                    constant(0, compared),
                )
            }
            // The destination is written: the borrow of a subtraction is the
            // difference plus the subtrahend wrapping below it, the carry of
            // an addition the sum below the addend, when the source stands.
            Producer::Arith {
                op: BinaryOp::Sub,
                rhs,
                result,
                same: false,
                ..
            } => {
                from.extend(rhs.from.iter().chain(&result.from).copied());
                let (r, result) = (self.node_of(rhs)?, self.node_of(result)?);
                let sum = Value::node(
                    AstNode::binary(result, BinaryOp::Add, r),
                    compared,
                    Vec::new(),
                );
                unsigned_less(self, &sum, rhs)?
            }
            Producer::Arith {
                op: BinaryOp::Add,
                rhs,
                result,
                same: false,
                ..
            } => {
                from.extend(rhs.from.iter().chain(&result.from).copied());
                unsigned_less(self, result, rhs)?
            }
            Producer::Test(..)
            | Producer::Arith {
                op: BinaryOp::And | BinaryOp::Or | BinaryOp::Xor,
                ..
            } => constant(0, bits),
            Producer::Bit(value, index) => {
                from.extend(value.from.iter().chain(&index.from).copied());
                let (value, index) = (self.node_of(value)?, self.node_of(index)?);
                AstNode::binary(
                    AstNode::binary(value, BinaryOp::Shr, index),
                    BinaryOp::And,
                    constant(1, bits),
                )
            }
            Producer::Arith { .. } | Producer::Result(_) => {
                return Err(NotLifted::new(format!(
                    "{} at {:#x} reads the carry of the {} at {:#x}, which its result does not say",
                    mnemonic_name(ins),
                    ins.address,
                    flags.mnemonic,
                    flags.at
                )))
            }
        };
        Ok(Value::node(node, bits, sorted(from)))
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
        self.state.flags.clear();
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
        let mnemonic = Mnemonic::try_from(ins.mnemonic as usize).unwrap_or(Mnemonic::INVALID);
        let cc = cc_of(mnemonic, "j").ok_or_else(|| NotLifted::new(mnemonic_name(ins)))?;
        self.condition_of(cc, ins)
    }

    /// The condition `cc` holds under, read back from what set the flags it
    /// reads — a jump, a `setcc` or a `cmovcc` at `ins` consuming them — and
    /// the addresses the condition came from.
    fn condition_of(
        &mut self,
        cc: Cc,
        ins: &DecodedInsn,
    ) -> Result<(AstNode, Vec<u64>), NotLifted> {
        let at = ins.address;
        let jcc = mnemonic_name(ins);
        let flags = self.state.flags.producer_of(cc.reads(), &jcc, at)?;
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
                    Cc::S | Cc::Ns | Cc::P | Cc::Np | Cc::O | Cc::No => return Err(unfit()),
                }
            }
            // An arithmetic instruction has written its destination, so its
            // operands' values may be gone: the relations are read from the
            // result — the zero and sign flags are its — and the carry of an
            // addition from the result and the source, which stands when it
            // is not the destination too. The logical operations clear the
            // carry and the overflow, so every relation is the result's.
            Producer::Arith {
                op,
                lhs,
                rhs,
                result,
                same,
            } => {
                addresses.extend(lhs.from.iter().chain(&rhs.from).copied());
                addresses.extend(result.from.iter().copied());
                let r = self.node_of(rhs)?;
                let result = self.node_of(result)?;
                let unsigned_op = |op, l: AstNode, r: AstNode| match self.options.unsigned_compare {
                    UnsignedCompare::Cast => {
                        AstNode::binary(unsigned(l, bits), op, unsigned(r, bits))
                    }
                    UnsignedCompare::Bare => AstNode::binary(l, op, r),
                };
                let of_result = |op| AstNode::binary(result.clone(), op, zero.clone());
                match (op, cc, same) {
                    (_, Cc::E, _) => of_result(BinaryOp::Equal),
                    (_, Cc::Ne, _) => of_result(BinaryOp::NotEqual),
                    (_, Cc::S, _) => of_result(BinaryOp::Less),
                    (_, Cc::Ns, _) => of_result(BinaryOp::GreaterEqual),
                    // A carry out of an addition: the sum wrapped below the
                    // addend that still stands.
                    (BinaryOp::Add, Cc::B, false) => unsigned_op(BinaryOp::Less, result, r),
                    (BinaryOp::Add, Cc::Ae, false) => {
                        unsigned_op(BinaryOp::GreaterEqual, result, r)
                    }
                    // A borrow out of a subtraction: the difference plus the
                    // subtrahend wrapped below it.
                    (BinaryOp::Sub, Cc::B, false) => unsigned_op(
                        BinaryOp::Less,
                        AstNode::binary(result, BinaryOp::Add, r.clone()),
                        r,
                    ),
                    (BinaryOp::Sub, Cc::Ae, false) => unsigned_op(
                        BinaryOp::GreaterEqual,
                        AstNode::binary(result, BinaryOp::Add, r.clone()),
                        r,
                    ),
                    (BinaryOp::And | BinaryOp::Or | BinaryOp::Xor, Cc::B, _) => {
                        AstNode::ConditionFalse
                    }
                    (BinaryOp::And | BinaryOp::Or | BinaryOp::Xor, Cc::Ae, _) => {
                        AstNode::ConditionTrue
                    }
                    (BinaryOp::And | BinaryOp::Or | BinaryOp::Xor, Cc::Be, _) => {
                        of_result(BinaryOp::Equal)
                    }
                    (BinaryOp::And | BinaryOp::Or | BinaryOp::Xor, Cc::A, _) => {
                        of_result(BinaryOp::NotEqual)
                    }
                    (BinaryOp::And | BinaryOp::Or | BinaryOp::Xor, Cc::L, _) => {
                        of_result(BinaryOp::Less)
                    }
                    (BinaryOp::And | BinaryOp::Or | BinaryOp::Xor, Cc::Ge, _) => {
                        of_result(BinaryOp::GreaterEqual)
                    }
                    (BinaryOp::And | BinaryOp::Or | BinaryOp::Xor, Cc::Le, _) => {
                        of_result(BinaryOp::LessEqual)
                    }
                    (BinaryOp::And | BinaryOp::Or | BinaryOp::Xor, Cc::G, _) => {
                        of_result(BinaryOp::Greater)
                    }
                    _ => return Err(unfit()),
                }
            }
            // The carry is the bit tested.
            Producer::Bit(value, index) => {
                addresses.extend(value.from.iter().chain(&index.from).copied());
                let bit = AstNode::binary(
                    AstNode::binary(self.node_of(value)?, BinaryOp::Shr, self.node_of(index)?),
                    BinaryOp::And,
                    constant(1, bits),
                );
                match cc {
                    Cc::B => AstNode::binary(bit, BinaryOp::NotEqual, zero),
                    Cc::Ae => AstNode::binary(bit, BinaryOp::Equal, zero),
                    _ => return Err(unfit()),
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
                        // The carry is clear: below never, above when not zero.
                        Cc::B => return Ok((AstNode::ConditionFalse, sorted(addresses))),
                        Cc::Ae => return Ok((AstNode::ConditionTrue, sorted(addresses))),
                        Cc::Be => BinaryOp::Equal,
                        Cc::A => BinaryOp::NotEqual,
                        Cc::P | Cc::Np | Cc::O | Cc::No => return Err(unfit()),
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
                // The address of a GOT slot, a selector reference or a class
                // reference is an address: what the slot holds is not where
                // it is.
                Some(Pointee::Data(_))
                | Some(Pointee::Import(_))
                | Some(Pointee::Selector(_))
                | Some(Pointee::ClassRef(_))
                | None => AstNode::constant(target, bits / 8),
            };
            Value::node(node, bits, vec![at])
        } else {
            self.address_of(base, index, scale, disp, bits, ins)?
        };
        self.assign(dest, bits, address.also_from(at), ins)
    }

    /// `rep movs` and `rep stos`: a copy or a fill of `rcx` elements through
    /// `rdi` (and `rsi`), as the `__builtin_memcpy` or `__builtin_memset`
    /// it stands for. The direction flag is taken as clear, as the ABI has
    /// it: `rdi` and `rsi` end past what was moved, and `rcx` at zero. The
    /// instruction without its prefix moves one element, and is not read.
    fn string_op(&mut self, fill: bool, ins: &DecodedInsn) -> Result<(), NotLifted> {
        // `movsd` is also the SSE move: the string form is memory to memory,
        // or a general register to memory, the memory operand's size the
        // element's.
        let width = match ins.operands.as_slice() {
            [Operand::Mem { size, .. }, Operand::Mem { .. }] if !fill && *size > 0 => *size,
            [Operand::Mem { size, .. }, Operand::Register(reg)]
                if fill && *size > 0 && reg.class == RC_GPR =>
            {
                *size
            }
            _ => return Err(NotLifted::new(mnemonic_name(ins))),
        };
        if !ins.rep {
            return Err(NotLifted::new(format!(
                "{} without rep",
                mnemonic_name(ins)
            )));
        }
        let at = ins.address;
        let count = self.read(RegisterId::new(RC_GPR, RCX, 64), at)?;
        let dest = self.read(RegisterId::new(RC_GPR, RDI, 64), at)?;
        let count_node = self.node_of(&count)?;
        let dest_node = self.node_of(&dest)?;
        let bytes_node = match count_node {
            _ if width == 1 => count_node,
            AstNode::Constant { value, .. } => {
                AstNode::constant(value.wrapping_mul(u64::from(width)), 8)
            }
            _ => AstNode::binary(
                count_node,
                BinaryOp::Mul,
                AstNode::constant(u64::from(width), 8),
            ),
        };
        // The frame the operation writes is whatever it leaves: the slots
        // under the destination forgotten, as far as the count says, or
        // all of them above it when the count is not known.
        if let Sym::Stack(start) = dest.sym {
            match bytes_node {
                AstNode::Constant { value, .. } if value < i64::MAX as u64 / 8 => {
                    self.kill(start, (value as u32).saturating_mul(8));
                }
                _ => self.state.stack.retain(|&offset, _| offset < start),
            }
        }
        let mut from: Vec<u64> = count.from.iter().chain(&dest.from).copied().collect();
        from.push(at);
        let (name, args) = if fill {
            let value = self.read(RegisterId::new(RC_GPR, RAX, width * 8), at)?;
            from.extend(value.from.iter().copied());
            let value_node = self.node_of(&value)?;
            (
                "__builtin_memset",
                vec![dest_node.clone(), value_node, bytes_node.clone()],
            )
        } else {
            let src = self.read(RegisterId::new(RC_GPR, RSI, 64), at)?;
            from.extend(src.from.iter().copied());
            let src_node = self.node_of(&src)?;
            self.state.regs.insert(
                RSI,
                Value::node(
                    AstNode::binary(src_node.clone(), BinaryOp::Add, bytes_node.clone()),
                    64,
                    vec![at],
                ),
            );
            (
                "__builtin_memcpy",
                vec![dest_node.clone(), src_node, bytes_node.clone()],
            )
        };
        // Memory was written through a pointer.
        self.memory_written(if fill { "the fill" } else { "the copy" }, at);
        let args = args
            .into_iter()
            .map(|node| Value::node(node, 64, vec![at]))
            .collect();
        self.statements.push(Stmt::Builtin {
            name,
            args,
            addresses: sorted(from),
        });
        self.state.regs.insert(
            RDI,
            Value::node(
                AstNode::binary(dest_node, BinaryOp::Add, bytes_node),
                64,
                vec![at],
            ),
        );
        self.state
            .regs
            .insert(RCX, Value::node(AstNode::constant(0, 8), 64, vec![at]));
        Ok(())
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

    /// A call: of the function a direct call names, or of the function a
    /// register or a memory operand holds — an import loaded from its slot,
    /// a function's address — when the lifter knows what it holds; a call
    /// through a value it does not know is refused.
    fn call(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        if let Flow::Call(target) = ins.flow {
            let name = self.function_named(target);
            return self.emit_call(name, target, ins.address);
        }
        let [operand] = ins.operands.as_slice() else {
            return Err(NotLifted::new("an indirect call"));
        };
        let value = self.value_of(operand, 64, ins)?;
        match self.callee_of(&value, ins.address, How::Call)? {
            // The guard's check validates the pointer in `rcx` and returns:
            // nothing the lift reads changes.
            None => Ok(()),
            Some(callee) => self.emit_callee(callee, ins.address),
        }
    }

    /// The name of the function at `target`: the image's, or one made of
    /// the address.
    fn function_named(&self, target: u64) -> String {
        self.symbols
            .function_name(target)
            .unwrap_or_else(|| format!("sub_{target:x}"))
    }

    /// What a call or a jump through `value` calls: a function the image
    /// names, the function at a constant address, the function in `rax`
    /// when the value is the control-flow guard's dispatcher, or — under
    /// `indirect-calls lift` — the value itself, an expression the call
    /// goes through. `None` for the guard's check, which calls nothing of
    /// the function's own. A value the lift does not know is refused, and
    /// so is a jump through an expression that is not a variable, which is
    /// a jump table the walk did not read, not a tail call.
    fn callee_of(&mut self, value: &Value, at: u64, how: How) -> Result<Option<Callee>, NotLifted> {
        self.callee_through(value, at, how, how)
    }

    /// [`Self::callee_of`], with `origin` the way the callee was first
    /// reached, for the refusal's wording after the dispatcher is followed.
    fn callee_through(
        &mut self,
        value: &Value,
        at: u64,
        how: How,
        origin: How,
    ) -> Result<Option<Callee>, NotLifted> {
        let refused = || match origin {
            How::Jump => NotLifted::new(format!("an indirect jump at {at:#x}")),
            How::Call | How::Dispatch => NotLifted::new("an indirect call"),
        };
        let node = match &value.sym {
            Sym::Node(node) => node.clone(),
            _ => return Err(refused()),
        };
        match self.guard_slot(&node) {
            // The dispatcher's target is the function in `rax`; a `rax` that
            // holds a guard pointer itself leads nowhere, and is refused
            // rather than followed round.
            Some(_) if how == How::Dispatch => return Err(refused()),
            Some(Guard::Check) => return Ok(None),
            Some(Guard::Dispatch) => {
                let target = self.read(RegisterId::new(RC_GPR, RAX, 64), at)?;
                return match self.callee_through(&target, at, How::Dispatch, origin)? {
                    Some(callee) => Ok(Some(callee)),
                    None => Err(refused()),
                };
            }
            None => {}
        }
        Ok(Some(match node {
            AstNode::FunctionName { name, address } => Callee::Named(name, address),
            AstNode::Constant { value: target, .. } => {
                Callee::Named(self.function_named(target), target)
            }
            expression => {
                if self.options.indirect_calls == IndirectCalls::Refuse
                    || (how == How::Jump && !matches!(expression, AstNode::Var { .. }))
                {
                    return Err(refused());
                }
                Callee::Through(expression)
            }
        }))
    }

    /// Which of the control-flow guard's pointers `node` is the contents
    /// of, when it is one: the variable the image names so, or a load from
    /// the slot's address.
    fn guard_slot(&self, node: &AstNode) -> Option<Guard> {
        let name = match node {
            AstNode::Var { name } => name.clone(),
            AstNode::Deref { target } => {
                let address = match target.as_ref() {
                    AstNode::Cast { target, .. } => target.as_ref(),
                    other => other,
                };
                let AstNode::Constant { value, .. } = address else {
                    return None;
                };
                match self.symbols.pointee(*value) {
                    Some(Pointee::Data(name)) => name,
                    _ => return None,
                }
            }
            _ => return None,
        };
        match name.as_str() {
            "__guard_dispatch_icall_fptr"
            | "__guard_xfg_dispatch_icall_fptr"
            | "__guard_xfg_table_dispatch_icall_fptr" => Some(Guard::Dispatch),
            "__guard_check_icall_fptr" | "__guard_xfg_check_icall_fptr" => Some(Guard::Check),
            _ => None,
        }
    }

    /// Call `callee` at `at`.
    fn emit_callee(&mut self, callee: Callee, at: u64) -> Result<(), NotLifted> {
        match callee {
            Callee::Named(name, address) => self.emit_call(name, address, at),
            Callee::Through(expression) => self.emit_call_through(expression, at),
        }
    }

    /// The function a `jmp` that leaves the function goes to, by name and
    /// address: the target of a direct jump when the image names it, or the
    /// function a register or a memory operand holds — a GOT slot's import,
    /// or a pointer loaded from one. Anything else is refused: a direct jump
    /// to an address the image does not name as `jumps to 0x…`, and a jump
    /// through a value that is not a function as `an indirect jump at 0x…`.
    fn jump_target(&mut self, ins: &DecodedInsn) -> Result<Callee, NotLifted> {
        let at = ins.address;
        // A target the image names nothing at is a routine of its own all
        // the same, called by its address.
        if let Flow::UnconditionalBranch(target) = ins.flow {
            return Ok(Callee::Named(self.function_named(target), target));
        }
        let [operand] = ins.operands.as_slice() else {
            return Err(NotLifted::new(format!(
                "jmp with {} operands",
                ins.operands.len()
            )));
        };
        let value = self.value_of(operand, 64, ins)?;
        match self.callee_of(&value, at, How::Jump)? {
            Some(callee) => Ok(callee),
            // A jump through the guard's check goes nowhere the lift knows.
            None => Err(NotLifted::new(format!("an indirect jump at {at:#x}"))),
        }
    }

    /// A `jmp` that leaves the function: the call and the return it stands
    /// for, `return callee(args);`, when the stack pointer is back at its
    /// entry value and the `tail-calls` option allows it.
    fn tail_jump(&mut self, ins: &DecodedInsn) -> Result<(), NotLifted> {
        let at = ins.address;
        let callee = if ins.flow == Flow::Next {
            // A fall into the next function: the instruction is this
            // function's own, and the call goes where it ends.
            self.step(ins)?;
            let next = at + ins.length as u64;
            Callee::Named(self.function_named(next), next)
        } else {
            self.jump_target(ins)?
        };
        if self.stack_pointer()? != 0 {
            return Err(NotLifted::new(format!(
                "the stack is not balanced at the jmp at {at:#x}"
            )));
        }
        if self.options.tail_calls == TailCalls::Refuse {
            return Err(NotLifted::new(format!(
                "a tail call to {} at {at:#x}",
                callee.label()
            )));
        }
        self.emit_callee(callee, at)?;
        self.ret(ins)
    }

    /// The callee of a function that is only a `jmp` to another function —
    /// behind at most `endbr64` and `nop`s — when `chains` are that; `None`
    /// for a function with a body of its own. The jump is resolved as any
    /// tail call's, so a jump the lifter cannot name, or one the
    /// `tail-calls` option refuses, is refused here.
    fn thunk(&mut self, chains: &[Chain]) -> Result<Option<String>, NotLifted> {
        let [chain] = chains else {
            return Ok(None);
        };
        if !matches!(chain.end, End::Leave) {
            return Ok(None);
        }
        let (last, body) = chain
            .instructions
            .split_last()
            .expect("a chain has an instruction");
        // A fall into the next function is no jump to name a thunk by.
        if last.flow == Flow::Next {
            return Ok(None);
        }
        let is_padding = |ins: &DecodedInsn| {
            matches!(
                Mnemonic::try_from(ins.mnemonic as usize),
                Ok(Mnemonic::Nop | Mnemonic::Endbr64)
            )
        };
        if !body.iter().all(is_padding) {
            return Ok(None);
        }
        // A thunk is a jump to a function by name; a jump through a value
        // is a function of its own, with the call in its body.
        let Callee::Named(name, _) = self.jump_target(last)? else {
            return Ok(None);
        };
        if self.options.tail_calls == TailCalls::Refuse {
            return Err(NotLifted::new(format!(
                "a tail call to {name} at {:#x}",
                last.address
            )));
        }
        Ok(Some(name))
    }

    /// The call of `name` at `target` from `at`: the arguments from the
    /// register state, the clobbers, and the result in `rax` as a temporary.
    fn emit_call(&mut self, name: String, target: u64, at: u64) -> Result<(), NotLifted> {
        self.call_sites.insert(at, target);
        let callee = AstNode::FunctionName {
            name: name.clone(),
            address: target,
        };
        self.emit_call_node(callee, name, Some(target), at)
    }

    /// A call through `expression` — a parameter, a field loaded from a
    /// struct — at `at`: `a(b, 1)`.
    fn emit_call_through(&mut self, expression: AstNode, at: u64) -> Result<(), NotLifted> {
        let label = one_line_of(&expression);
        self.emit_call_node(expression, label, None, at)
    }

    /// A call of `callee` — a function by name, or an expression — at `at`,
    /// `name` being what the callee is called in the reasons given later.
    fn emit_call_node(
        &mut self,
        callee: AstNode,
        name: String,
        target: Option<u64>,
        at: u64,
    ) -> Result<(), NotLifted> {
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
            // The guard's dispatcher loaded into a register is the call's
            // way, not an argument.
            if matches!(&value.sym, Sym::Node(node) if self.guard_slot(node).is_some()) {
                break;
            }
            let value = self.at_width(value.clone(), value.bits, register, at)?;
            addresses.extend(value.from.iter().copied());
            args.push(self.node_of(&value)?);
        }
        // A message send's arity is its selector's: the receiver, the
        // selector and one argument per colon. A register the block did
        // not write is then the function's own parameter, passed on — as
        // `self` is, in a method that sends itself a message.
        if is_dispatcher(&name) {
            let registers = self.abi.argument_registers().to_vec();
            let mut wanted = 2;
            while args.len() < wanted.min(registers.len()) {
                let register = registers[args.len()];
                // A selector stub loads the selector its name carries into
                // the second argument register itself.
                if args.len() == 1 {
                    if let Some(selector) = stub_selector(&name) {
                        args.push(AstNode::StringLiteral {
                            text: selector.to_string(),
                        });
                        wanted = message_arity(&name, &args).unwrap_or(wanted);
                        continue;
                    }
                }
                let value = self.read(RegisterId::new(RC_GPR, register, 64), at)?;
                if matches!(value.sym, Sym::Unknown(_)) {
                    break;
                }
                addresses.extend(value.from.iter().copied());
                args.push(self.node_of(&value)?);
                if let Some(arity) = message_arity(&name, &args) {
                    wanted = arity;
                }
            }
        }
        // What the callee's own lift says of when it does not return, said
        // of these arguments: `checked does not return when p == 0`.
        if let Some(target) = target {
            for (params, condition) in self.symbols.noreturn_when(target) {
                // Said only when every parameter the condition names has an
                // argument here to stand for it.
                if params
                    .iter()
                    .skip(args.len())
                    .any(|param| condition.reads_var(param))
                {
                    continue;
                }
                // All at once, through placeholders: an argument named as
                // a later parameter must not be substituted again.
                let placeholder = |i: usize| format!("__noreturn_arg_{i}");
                let mut condition = condition;
                for (i, param) in params.iter().enumerate().take(args.len()) {
                    condition = condition.substitute(param, &AstNode::var(placeholder(i)));
                }
                for (i, arg) in args.iter().enumerate().take(params.len()) {
                    condition = condition.substitute(&placeholder(i), arg);
                }
                let condition = condition.folded();
                // A condition the arguments decide against is no note.
                if matches!(condition, AstNode::ConstantCondition { holds: false, .. }) {
                    continue;
                }
                self.call_notes.push((at, name.clone(), condition));
            }
        }
        let callee_name = name;
        let node = AstNode::Call {
            callee: Box::new(callee),
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
        self.state.flags.clear();
        let temp = self.temps.len() + self.saved.len();
        self.temps.push(Temp {
            name: format!("v{}", temp + 1),
            bits: None,
            callee: callee_name,
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
        let held = self.state.regs.get(&RAX).cloned();
        // A call result exactly as the call left it — nothing of the
        // function's own went into it — is a leftover, and whether it is
        // returned is decided once every ret is seen.
        let leftover = match &held {
            Some(Value {
                sym: Sym::Temp(temp),
                from,
                ..
            }) if from.len() == 1 => Some(*temp),
            _ => None,
        };
        // The value is kept as it is: a call result's width is the width it
        // is read at, which the decision of the return fixes once every
        // ret is seen.
        let mut addresses = vec![at];
        if let Some(value) = &held {
            addresses.extend(value.from.iter().copied());
        }
        self.statements.push(Stmt::Return {
            value: held,
            leftover,
            addresses: sorted(addresses),
        });
        Ok(())
    }

    // ---- the return -------------------------------------------------------

    /// Decide whether the function returns a value, and at what width, from
    /// its `ret`s and from what its callers do with the result; record why.
    ///
    /// A function no `ret` of which has a value in `rax` is `void`. Under
    /// `return-liveness callers` the callers decide when the image knows
    /// them: one that reads the result makes every `ret` return at the width
    /// of the widest read, and a `ret` with nothing in `rax` is then a
    /// disagreement; callers that all discard it make the function `void`.
    /// With no caller in the image, a `ret` whose value is a callee's
    /// leftover that nothing else in the function reads returns nothing —
    /// unless another `ret` returns a value the function wrote itself, in
    /// which case the leftover path hands on the callee's result — and the
    /// `ret`s must agree on what is left. Under `presence` every value in
    /// `rax` counts, and the `ret`s must agree.
    fn decide_return(
        &mut self,
        entry: u64,
        lifted: &[(Vec<Stmt>, Terminator)],
    ) -> Result<(), NotLifted> {
        // Every ret: the width of the value in rax — a call result's is the
        // width it is read at, and one nothing reads has none of its own —
        // and the callee whose dead leftover that value is, when it is one:
        // a call result exactly as the call left it that nothing else in the
        // function reads, or what is left where such a result joined nothing.
        let presence = self.options.return_liveness == ReturnLiveness::Presence;
        let mut rets: Vec<(Option<Width>, Option<String>)> = Vec::new();
        for (statements, _) in lifted {
            for stmt in statements {
                let Stmt::Return {
                    value, leftover, ..
                } = stmt
                else {
                    continue;
                };
                let width = value.as_ref().map(|value| match value.sym {
                    Sym::Temp(temp) => match self.temps[temp].bits {
                        Some(bits) => Width::Fixed(bits),
                        // Under presence the width is the last write's, as
                        // it always was: a call writes 64 bits.
                        None if presence => Width::Fixed(64),
                        None => Width::Any,
                    },
                    Sym::Dead(_) if !presence => Width::Any,
                    _ => Width::Fixed(value.bits),
                });
                let dead = match value.as_ref().map(|value| &value.sym) {
                    Some(Sym::Dead(callee)) => Some(callee.clone()),
                    _ => leftover
                        .filter(|&temp| !self.result_is_read(lifted, temp))
                        .map(|temp| self.temps[temp].callee.clone()),
                };
                rets.push((width, dead));
            }
        }

        if rets.iter().all(|(width, _)| width.is_none()) {
            self.return_bits = None;
            self.return_reason = "no ret has a value in rax".to_string();
            return Ok(());
        }

        match self.options.return_liveness {
            ReturnLiveness::Presence => {
                self.return_bits = agree(rets.iter().map(|(width, _)| *width))?;
                self.return_reason = "rax holds a value at the ret".to_string();
            }
            ReturnLiveness::Callers => {
                match callers_verdict(self.symbols, entry, &mut BTreeSet::from([entry])) {
                    Verdict::Read { bits, reason } => {
                        if rets.iter().any(|(width, _)| width.is_none()) {
                            return Err(NotLifted::new(
                                "returns a value at one ret and nothing at another",
                            ));
                        }
                        self.return_bits = Some(bits);
                        self.return_reason = reason;
                    }
                    Verdict::Ignored => {
                        self.return_bits = None;
                        self.return_reason = "no caller reads the result".to_string();
                    }
                    Verdict::Unknown => {
                        // A leftover is dead only when no ret returns a
                        // value the function wrote itself; when one does,
                        // the leftover paths hand on the callee's result.
                        let own = rets
                            .iter()
                            .any(|(width, dead)| width.is_some() && dead.is_none());
                        let live =
                            rets.iter().map(
                                |(width, dead)| {
                                    if dead.is_some() && !own {
                                        None
                                    } else {
                                        *width
                                    }
                                },
                            );
                        self.return_bits = agree(live)?;
                        self.return_reason = match self.return_bits {
                            Some(_) => "no caller in the image, and the function writes rax \
                                        itself before the ret"
                                .to_string(),
                            None => {
                                let callee = rets
                                    .iter()
                                    .find_map(|(_, dead)| dead.clone())
                                    .expect("a ret has a value, and it is a leftover");
                                format!(
                                    "no caller in the image, and rax at the ret holds only \
                                     {callee}'s result, which nothing reads"
                                )
                            }
                        };
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether anything in the function reads the call result `temp` — a
    /// statement, a store into a variable, a condition — the `ret`s that
    /// return it untouched aside.
    fn result_is_read(&self, lifted: &[(Vec<Stmt>, Terminator)], temp: usize) -> bool {
        let name = self.temps[temp].name.as_str();
        let mentions = |value: &Value| {
            matches!(value.sym, Sym::Temp(other) if other == temp) || value.reads_var(name)
        };
        lifted.iter().any(|(statements, terminator)| {
            statements.iter().any(|stmt| match stmt {
                Stmt::Return {
                    leftover: Some(other),
                    ..
                } if *other == temp => false,
                Stmt::Return { value, .. } => value.as_ref().is_some_and(mentions),
                Stmt::Call { node, .. } => node.reads_var(name),
                // A store to a slot that is not a variable only carries the
                // value, and the load that reads it back is the read.
                Stmt::Store { offset, value, .. } => {
                    self.locals.contains_key(offset) && mentions(value)
                }
                Stmt::Assign { lhs, value, .. } => lhs.reads_var(name) || mentions(value),
                Stmt::Compare { lhs, rhs, .. } => mentions(lhs) || mentions(rhs),
                Stmt::Builtin { args, .. } => args.iter().any(&mentions),
            }) || matches!(terminator, Terminator::Branch { cond, .. } if cond.reads_var(name))
        })
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
                        // A note that named the result names the call now.
                        for (_, _, condition) in &mut self.call_notes {
                            if condition.reads_var(&name) {
                                *condition = condition.clone().substitute(&name, &call);
                            }
                        }
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
                            // A call's result, held in the accumulator.
                            declared.push(
                                Variable::new(type_name(bits), name.clone())
                                    .placed(Placement::register(RAX, bits)),
                            );
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
        let registers = self.abi.argument_registers();
        let params = (0..count)
            .map(|position| {
                let bits = self.params.get(&position).copied();
                let variable =
                    Variable::new(bits.map_or("long", type_name), parameter_name(position));
                match registers.get(position) {
                    Some(&index) => variable.placed(Placement::register(index, bits.unwrap_or(64))),
                    None => variable,
                }
            })
            .collect();

        // The locals nearest the frame first, then the registers that
        // became variables, then the temporaries.
        let mentioned = |name: &str| body.iter().any(|statement| statement.mentions(name));
        let mut locals: Vec<Variable> = self
            .locals
            .iter()
            .rev()
            .map(|(&offset, &bits)| {
                Variable::new(
                    type_name(bits),
                    local_name(self.options.stack_slot_names, offset),
                )
                .placed(Placement::Stack {
                    offset,
                    size: bits / 8,
                })
            })
            .collect();
        let mut merged: Vec<(u32, &Merged)> = self
            .merged
            .iter()
            .map(|(&(_, index), merged)| (index, merged))
            .collect();
        merged.sort_by(|(_, a), (_, b)| a.name.cmp(&b.name));
        locals.extend(
            merged
                .into_iter()
                .filter(|(_, merged)| mentioned(&merged.name))
                .map(|(index, merged)| {
                    Variable::new(type_name(merged.bits), merged.name.clone())
                        .placed(Placement::register(index, merged.bits))
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

        // What the body says of the function's return besides the width:
        // that it never comes back, or does not under a condition. A path
        // the walk did not follow may come back, for all the lift knows.
        let never_returns = !body.is_empty()
            && !any_statement(&body, &|statement| {
                matches!(statement.node, AstNode::Return { .. })
                    || halted_target(&statement.node).is_some()
            });
        let local_names: Vec<String> = locals.iter().map(|local| local.name.clone()).collect();
        let noreturn_when = if never_returns {
            Vec::new()
        } else {
            noreturn_conditions(&body, &local_names)
        };
        let mut notes = Vec::new();
        if never_returns {
            notes.push("does not return".to_string());
        }
        for condition in &noreturn_when {
            notes.push(format!("does not return when {}", one_line_of(condition)));
        }
        Ok(LiftedFunction {
            name: name.to_string(),
            address: entry,
            return_type: self.return_bits.map_or("void", type_name).to_string(),
            params,
            locals,
            body,
            frame,
            notes,
            call_notes: self
                .call_notes
                .into_iter()
                .map(|(at, callee, condition)| CallNote {
                    at,
                    text: match &condition {
                        AstNode::ConstantCondition { holds: true, .. } => {
                            format!("{callee} does not return")
                        }
                        condition => {
                            format!("{callee} does not return when {}", one_line_of(condition))
                        }
                    },
                    callee,
                })
                .collect(),
            noreturn_when,
            thunk: None,
            return_reason: Some(self.return_reason),
        })
    }
}

/// The width of the value a `ret` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Width {
    /// Written at, or read at, this many bits.
    Fixed(u32),
    /// A call result nothing reads: whatever width the function returns at.
    Any,
}

/// The one width every `ret` returns at — `None` for none — or the
/// disagreement, refused: a value at one `ret` and nothing at another, or
/// two fixed widths. Widths that are anything agree with any width, and are
/// 64 bits when nothing fixes them.
fn agree(decisions: impl IntoIterator<Item = Option<Width>>) -> Result<Option<u32>, NotLifted> {
    let mut fixed: Option<u32> = None;
    let mut value = false;
    let mut nothing = false;
    for decision in decisions {
        match decision {
            None => nothing = true,
            Some(Width::Any) => value = true,
            Some(Width::Fixed(bits)) => {
                value = true;
                match fixed {
                    None => fixed = Some(bits),
                    Some(known) if known == bits => {}
                    Some(known) => {
                        return Err(NotLifted::new(format!(
                            "returns {known} bits at one ret and {bits} at another"
                        )))
                    }
                }
            }
        }
    }
    if value && nothing {
        return Err(NotLifted::new(
            "returns a value at one ret and nothing at another",
        ));
    }
    Ok(value.then(|| fixed.unwrap_or(64)))
}

/// What the callers the image knows do with a function's result.
enum Verdict {
    /// Some caller reads it; `bits` is the widest read, and `reason` names
    /// the caller: `main reads eax after the call`.
    Read { bits: u32, reason: String },
    /// Every caller writes or ignores it.
    Ignored,
    /// The image knows no caller.
    Unknown,
}

/// What the callers of the function at `address` do with its result. A
/// caller that carries the result untouched to its own `ret` is asked about
/// in turn — its callers decide — with `visited` keeping a cycle of such
/// callers from being followed twice; a chain that ends in a function with
/// no caller reads nothing, by the rule for a function with no caller.
fn callers_verdict(symbols: &dyn Symbols, address: u64, visited: &mut BTreeSet<u64>) -> Verdict {
    let uses = symbols.result_uses(address);
    if uses.is_empty() {
        return Verdict::Unknown;
    }
    let mut widest: Option<(u32, String)> = None;
    let mut consider = |bits: u32, reason: String| {
        if widest.as_ref().is_none_or(|(known, _)| bits > *known) {
            widest = Some((bits, reason));
        }
    };
    for site in uses {
        match site.result {
            ResultUse::Read { bits } => consider(
                bits,
                format!(
                    "{} reads {} after the call",
                    site.caller_name,
                    rax_name(bits)
                ),
            ),
            ResultUse::Killed => {}
            ResultUse::Returned => {
                if !visited.insert(site.caller) {
                    continue;
                }
                if let Verdict::Read { bits, reason } =
                    callers_verdict(symbols, site.caller, visited)
                {
                    consider(
                        bits,
                        format!("{} returns it, and {reason}", site.caller_name),
                    );
                }
            }
        }
    }
    match widest {
        Some((bits, reason)) => Verdict::Read { bits, reason },
        None => Verdict::Ignored,
    }
}

/// A condition code, as the conditional jumps spell it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cc {
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
    P,
    Np,
    O,
    No,
}

impl Cc {
    /// The flags the condition reads, as the decoder's bits.
    fn reads(self) -> u32 {
        match self {
            Cc::E | Cc::Ne => ZF,
            Cc::L | Cc::Ge => SF | OF,
            Cc::Le | Cc::G => ZF | SF | OF,
            Cc::B | Cc::Ae => CF,
            Cc::Be | Cc::A => CF | ZF,
            Cc::S | Cc::Ns => SF,
            Cc::P | Cc::Np => PF,
            Cc::O | Cc::No => OF,
        }
    }
}

/// The condition code of a conditional instruction of the `family` — `j`,
/// `set` or `cmov` — or `None` for another instruction.
pub(crate) fn cc_of(mnemonic: Mnemonic, family: &str) -> Option<Cc> {
    let name = format!("{mnemonic:?}").to_ascii_lowercase();
    let suffix = name.strip_prefix(family)?;
    Some(match suffix {
        "e" | "z" => Cc::E,
        "ne" | "nz" => Cc::Ne,
        "l" | "nge" => Cc::L,
        "ge" | "nl" => Cc::Ge,
        "le" | "ng" => Cc::Le,
        "g" | "nle" => Cc::G,
        "b" | "c" | "nae" => Cc::B,
        "ae" | "nc" | "nb" => Cc::Ae,
        "be" | "na" => Cc::Be,
        "a" | "nbe" => Cc::A,
        "s" => Cc::S,
        "ns" => Cc::Ns,
        "p" | "pe" => Cc::P,
        "np" | "po" => Cc::Np,
        "o" => Cc::O,
        "no" => Cc::No,
        _ => return None,
    })
}

/// A statement resolved to a node: the temporary it defines, if it is a
/// call, the node, and the addresses it came from.
type Resolved = (Option<usize>, AstNode, Vec<u64>);

impl Lifter<'_> {
    /// The statements as nodes, with the stores to slots that are not
    /// variables left out.
    fn resolve(&mut self, statements: &[Stmt]) -> Result<Vec<Resolved>, NotLifted> {
        let mut resolved: Vec<Resolved> = Vec::new();
        self.string_run = None;
        for stmt in statements {
            if !matches!(stmt, Stmt::Store { .. }) {
                self.string_run = None;
            }
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
                    let width = i64::from(bits / 8);
                    let constant = matches!(value.sym, Sym::Node(AstNode::Constant { .. }));
                    if !self.locals.contains_key(offset) {
                        let overlapping: Vec<i64> = self
                            .locals
                            .iter()
                            .filter(|(&local, &bits)| {
                                local < offset + width && *offset < local + i64::from(bits / 8)
                            })
                            .map(|(&local, _)| local)
                            .collect();
                        let into = match overlapping.as_slice() {
                            // A constant store right after the last constant
                            // store to or into a variable continues it: the
                            // next word, or byte, of a string on the stack.
                            [] => match self.string_run {
                                Some((local, end)) if constant && end == *offset => Some(local),
                                _ => None,
                            },
                            // A store into the middle of one variable — the
                            // second word of a string put on the stack — is a
                            // store through a pointer into it.
                            [local] if *local <= *offset => Some(*local),
                            // Into two variables, or starting before one:
                            // what the code means is not told apart.
                            [local, ..] => {
                                return Err(NotLifted::new(format!(
                                    "a partial write to {}",
                                    local_name(self.options.stack_slot_names, *local)
                                )));
                            }
                        };
                        let Some(local) = into else {
                            self.string_run = None;
                            continue;
                        };
                        let rhs = self.node_of(value)?;
                        let base = AstNode::Cast {
                            ty: "char *".to_string(),
                            target: Box::new(AstNode::AddressOf {
                                target: Box::new(AstNode::var(local_name(
                                    self.options.stack_slot_names,
                                    local,
                                ))),
                            }),
                        };
                        let pointer = AstNode::binary(
                            base,
                            BinaryOp::Add,
                            AstNode::constant((*offset - local) as u64, 8),
                        );
                        let node = AstNode::Assign {
                            lhs: Box::new(AstNode::Deref {
                                target: Box::new(AstNode::Cast {
                                    ty: format!("{} *", type_name(*bits)),
                                    target: Box::new(pointer),
                                }),
                            }),
                            rhs: Box::new(rhs),
                        };
                        resolved.push((None, node, addresses.clone()));
                        self.string_run = constant.then_some((local, offset + width));
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
                    self.string_run = constant.then_some((*offset, offset + width));
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
                Stmt::Builtin {
                    name,
                    args,
                    addresses,
                } => {
                    let mut nodes = Vec::with_capacity(args.len());
                    for arg in args {
                        nodes.push(self.node_of(arg)?);
                    }
                    resolved.push((
                        None,
                        AstNode::Intrinsic {
                            name: name.to_string(),
                            args: nodes,
                        },
                        addresses.clone(),
                    ));
                }
                Stmt::Return {
                    value, addresses, ..
                } => {
                    // A value nothing returns is dropped, and one returned
                    // at another width than it was written is cast. A call
                    // result nothing read is read here, at the width the
                    // function returns at.
                    let value = match (value, self.return_bits) {
                        (Some(value), Some(bits)) => {
                            let had = match value.sym {
                                Sym::Temp(temp) => *self.temps[temp].bits.get_or_insert(bits),
                                _ => value.bits,
                            };
                            let node = self.node_of(value)?;
                            Some(Box::new(if had == bits {
                                node
                            } else {
                                cast(node, had, bits)
                            }))
                        }
                        _ => None,
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
        if self.options.builtins == Builtins::Recognize {
            self.merge_stack_strings(&mut resolved);
        }
        if self.options.struct_initializers == StructInitializers::Recognize {
            merge_struct_initializers(&mut resolved);
        }
        Ok(resolved)
    }

    /// A string put on the stack word by word — consecutive stores of
    /// constants to one variable and into it, whose bytes read as text —
    /// becomes one `__builtin_strcpy(&local, "text")`, or a
    /// `__builtin_memcpy` of the bytes where no NUL ends them. Two stores
    /// at least, so that one wide constant is left the number it may be.
    fn merge_stack_strings(&self, resolved: &mut Vec<Resolved>) {
        let names = self.options.stack_slot_names;
        let offsets: BTreeMap<String, i64> = self
            .locals
            .keys()
            .map(|&offset| (local_name(names, offset), offset))
            .collect();
        // The store a statement is, when it is one of a constant to a
        // variable or into it: the variable's offset, then the store's
        // offset, the width in bytes and the value.
        let store = |node: &AstNode| -> Option<(i64, (i64, u32, u64))> {
            let AstNode::Assign { lhs, rhs } = node else {
                return None;
            };
            let AstNode::Constant { value, width_bytes } = rhs.as_ref() else {
                return None;
            };
            match lhs.as_ref() {
                AstNode::Var { name } => {
                    let offset = *offsets.get(name)?;
                    Some((offset, (offset, *width_bytes, *value)))
                }
                AstNode::Deref { target } => {
                    let AstNode::Cast { target, .. } = target.as_ref() else {
                        return None;
                    };
                    let AstNode::Binary {
                        lhs,
                        op: BinaryOp::Add,
                        rhs,
                    } = target.as_ref()
                    else {
                        return None;
                    };
                    let AstNode::Constant { value: past, .. } = rhs.as_ref() else {
                        return None;
                    };
                    let AstNode::Cast { target, .. } = lhs.as_ref() else {
                        return None;
                    };
                    let AstNode::AddressOf { target } = target.as_ref() else {
                        return None;
                    };
                    let AstNode::Var { name } = target.as_ref() else {
                        return None;
                    };
                    let local = *offsets.get(name)?;
                    Some((local, (local + *past as i64, *width_bytes, *value)))
                }
                _ => None,
            }
        };
        let mut i = 0;
        while i < resolved.len() {
            let mut j = i;
            let mut run: Vec<(i64, u32, u64)> = Vec::new();
            // The run is one variable's: a store to another variable is
            // that variable's own, however the bytes read.
            let mut variable: Option<i64> = None;
            while j < resolved.len() {
                let (temp, node, _) = &resolved[j];
                match (temp, store(node)) {
                    (None, Some((local, found)))
                        if variable.is_none_or(|variable| variable == local) =>
                    {
                        variable = Some(local);
                        run.push(found);
                    }
                    _ => break,
                }
                j += 1;
            }
            if run.len() >= 2 {
                if let Some((start, name, args)) = stack_string(&run) {
                    if Some(start) == variable {
                        let mut addresses: Vec<u64> = resolved[i..j]
                            .iter()
                            .flat_map(|(_, _, addresses)| addresses.iter().copied())
                            .collect();
                        addresses = sorted(addresses);
                        let mut full = vec![AstNode::AddressOf {
                            target: Box::new(AstNode::var(local_name(names, start))),
                        }];
                        full.extend(args);
                        resolved.splice(
                            i..j,
                            [(
                                None,
                                AstNode::Intrinsic {
                                    name: name.to_string(),
                                    args: full,
                                },
                                addresses,
                            )],
                        );
                        i += 1;
                        continue;
                    }
                }
            }
            i = j.max(i + 1);
        }
    }
}

// ---- helpers --------------------------------------------------------------

/// A run of stores through one pointer at distinct offsets — `*(T *)p`,
/// `*(T *)(p + k)` — becomes one struct initializer: the pointer cast to a
/// struct of the fields by offset, assigned the values in order. Two stores
/// at least; the pointer no constant, so that the globals an address names
/// stay their own; the fields not overlapping; and no value reading memory
/// or calling, since the initializer stores them all at once.
fn merge_struct_initializers(resolved: &mut Vec<Resolved>) {
    // The store a statement is, when it is one through a pointer at an
    // offset: the pointer, the offset, the pointee type and the value.
    let store = |node: &AstNode| -> Option<(AstNode, u64, String, AstNode)> {
        let AstNode::Assign { lhs, rhs } = node else {
            return None;
        };
        let AstNode::Deref { target } = lhs.as_ref() else {
            return None;
        };
        let AstNode::Cast { ty, target } = target.as_ref() else {
            return None;
        };
        let pointee = ty.trim_end().strip_suffix('*')?.trim();
        if pointee.is_empty() || pointee.starts_with("struct {") {
            return None;
        }
        let (base, offset) = match target.as_ref() {
            AstNode::Binary {
                lhs,
                op: BinaryOp::Add,
                rhs,
            } => match rhs.as_ref() {
                AstNode::Constant { value, .. } => ((**lhs).clone(), *value),
                _ => return None,
            },
            other => (other.clone(), 0),
        };
        // A struct's fields lie close to its start: an offset far from the
        // pointer is an address — a global array indexed by a variable, whose
        // store is its own.
        if base.is_constant() || offset >= 4096 {
            return None;
        }
        let touches_memory = |node: &AstNode| {
            node.any(&|n| {
                matches!(
                    n,
                    AstNode::Deref { .. }
                        | AstNode::Call { .. }
                        | AstNode::Intrinsic { .. }
                        | AstNode::Assign { .. }
                        | AstNode::StructInit { .. }
                )
            })
        };
        // The pointer is read once for the initializer, so it must not come
        // from memory a field could write.
        if touches_memory(&base) {
            return None;
        }
        let reads_memory = rhs.any(&|n| {
            matches!(
                n,
                AstNode::Deref { .. }
                    | AstNode::Call { .. }
                    | AstNode::Intrinsic { .. }
                    | AstNode::Assign { .. }
                    | AstNode::StructInit { .. }
            )
        });
        if reads_memory {
            return None;
        }
        Some((base, offset, pointee.to_string(), (**rhs).clone()))
    };
    let width = |ty: &str| -> u64 {
        if ty.ends_with('*') {
            8
        } else {
            u64::from(crate::emulate::type_of(ty).0 / 8)
        }
    };
    let mut i = 0;
    while i < resolved.len() {
        let mut j = i;
        let mut run: Vec<(u64, String, AstNode)> = Vec::new();
        let mut base: Option<AstNode> = None;
        while j < resolved.len() {
            let (temp, node, _) = &resolved[j];
            let Some((pointer, offset, ty, value)) =
                (temp.is_none()).then(|| store(node)).flatten()
            else {
                break;
            };
            if base.as_ref().is_some_and(|base| *base != pointer) {
                break;
            }
            // A field written twice, or one over another, ends the run.
            let overlaps = run.iter().any(|(other, other_ty, _)| {
                offset < other.saturating_add(width(other_ty))
                    && *other < offset.saturating_add(width(&ty))
            });
            if overlaps {
                break;
            }
            base.get_or_insert(pointer);
            run.push((offset, ty, value));
            j += 1;
        }
        if run.len() >= 2 {
            let base = base.expect("a run has a pointer");
            run.sort_by_key(|(offset, _, _)| *offset);
            let fields: Vec<StructField> = run
                .into_iter()
                .map(|(offset, ty, value)| StructField { ty, offset, value })
                .collect();
            let struct_type = format!(
                "struct {{ {} }} *",
                fields
                    .iter()
                    .map(|field| format!("{} {};", field.ty, field.name()))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            let addresses = sorted(
                resolved[i..j]
                    .iter()
                    .flat_map(|(_, _, addresses)| addresses.iter().copied()),
            );
            let node = AstNode::Assign {
                lhs: Box::new(AstNode::Deref {
                    target: Box::new(AstNode::Cast {
                        ty: struct_type,
                        target: Box::new(base),
                    }),
                }),
                rhs: Box::new(AstNode::StructInit { fields }),
            };
            resolved.splice(i..j, [(None, node, addresses)]);
            i += 1;
            continue;
        }
        i = j.max(i + 1);
    }
}

/// The string a run of constant stores puts on the stack: the lowest
/// offset written, the builtin that reads it back and the arguments after
/// the destination — the text, and for a memcpy the byte count. The stores
/// must cover their span without a gap, later ones over earlier, and the
/// bytes must read as two or more printable characters ending in NULs
/// (`__builtin_strcpy`) or nothing but printable characters
/// (`__builtin_memcpy`).
fn stack_string(run: &[(i64, u32, u64)]) -> Option<(i64, &'static str, Vec<AstNode>)> {
    let mut bytes: BTreeMap<i64, u8> = BTreeMap::new();
    for &(offset, width, value) in run {
        for byte in 0..i64::from(width) {
            bytes.insert(offset + byte, (value >> (8 * byte)) as u8);
        }
    }
    let start = *bytes.keys().next()?;
    let end = *bytes.keys().next_back()? + 1;
    if (end - start) as usize != bytes.len() {
        return None;
    }
    let flat: Vec<u8> = bytes.into_values().collect();
    let printable =
        |byte: u8| (0x20..=0x7e).contains(&byte) || matches!(byte, b'\t' | b'\n' | b'\r');
    let text_end = flat
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(flat.len());
    if text_end < 2 || !flat[..text_end].iter().all(|&byte| printable(byte)) {
        return None;
    }
    let text = String::from_utf8(flat[..text_end].to_vec()).ok()?;
    if text_end == flat.len() {
        return Some((
            start,
            "__builtin_memcpy",
            vec![
                AstNode::StringLiteral { text },
                AstNode::constant(flat.len() as u64, 8),
            ],
        ));
    }
    if !flat[text_end..].iter().all(|&byte| byte == 0) {
        return None;
    }
    Some((
        start,
        "__builtin_strcpy",
        vec![AstNode::StringLiteral { text }],
    ))
}

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
pub(crate) fn local_name(names: SlotNames, offset: i64) -> String {
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

/// Whether `callee` is the Objective-C runtime's dispatcher, or one of its
/// variants — the names of a message send — or a selector stub,
/// `objc_msgSend$sel`, which loads the selector itself before it
/// dispatches.
fn is_dispatcher(callee: &str) -> bool {
    let name = callee.strip_prefix('_').unwrap_or(callee);
    if name.strip_prefix("objc_msgSend$").is_some() {
        return true;
    }
    matches!(
        name.strip_prefix("objc_msgSend"),
        Some(
            "" | "_fpret"
                | "_fp2ret"
                | "_stret"
                | "Super"
                | "Super2"
                | "Super_stret"
                | "Super2_stret"
        )
    )
}

/// The selector a selector stub's name carries: `greet:` of
/// `objc_msgSend$greet:`.
fn stub_selector(callee: &str) -> Option<&str> {
    let name = callee.strip_prefix('_').unwrap_or(callee);
    name.strip_prefix("objc_msgSend$")
}

/// How many arguments a call of the Objective-C dispatcher takes, when the
/// callee is one and the selector is known: the receiver, the selector and
/// one per colon of the selector, the result's address first for a
/// struct-returning send. `None` for any other call, and until the
/// selector is known.
fn message_arity(callee: &str, args: &[AstNode]) -> Option<usize> {
    if !is_dispatcher(callee) {
        return None;
    }
    let name = callee.strip_prefix('_').unwrap_or(callee);
    let returns_struct = name.ends_with("_stret");
    let skip = usize::from(returns_struct);
    let AstNode::StringLiteral { text } = args.get(skip + 1)? else {
        return None;
    };
    Some(skip + 2 + text.matches(':').count())
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
pub(crate) fn gpr_name(index: u32, bits: u32) -> String {
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
    use crate::emit::{emit_function, Pseudocode};

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

    /// The C of `bytes`, or the reason it was not lifted. The leading
    /// comment that records the return decision is left out, so the tests
    /// read the signature and the body alone; the tests of the decision
    /// read the comment through [`decided`].
    fn c(bytes: &[u8]) -> String {
        match lift(bytes) {
            Ok(function) => without_reason(&emit_function(&function, &Options::default())),
            Err(error) => error.to_string(),
        }
    }

    /// The C of `bytes` with the options `pairs` set, lifted against
    /// `symbols`, or the reason it was not lifted; the reason comment left
    /// out as in [`c`].
    fn c_with(bytes: &[u8], symbols: &dyn Symbols, pairs: &[(&str, &str)]) -> String {
        let options = Options::from_pairs(pairs.iter().copied()).expect("the options are known");
        match lift_block(&decode(bytes), BASE, "f", Abi::SystemV, symbols, &options) {
            Ok(function) => without_reason(&emit_function(&function, &options)),
            Err(error) => error.to_string(),
        }
    }

    /// The text of `pseudocode` without the `// void: …` or `// returns …:
    /// …` comment that opens it.
    fn without_reason(pseudocode: &Pseudocode) -> String {
        pseudocode
            .lines
            .iter()
            .map(|line| line.text.as_str())
            .filter(|text| !(text.starts_with("// void: ") || text.starts_with("// returns ")))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The return decision of `bytes` lifted against `symbols` with `pairs`
    /// set: the comment that opens the pseudocode, which says the type and
    /// what decided it.
    fn decided(bytes: &[u8], symbols: &dyn Symbols, pairs: &[(&str, &str)]) -> String {
        let options = Options::from_pairs(pairs.iter().copied()).expect("the options are known");
        let function = lift_block(&decode(bytes), BASE, "f", Abi::SystemV, symbols, &options)
            .expect("the code lifts");
        let pseudocode = emit_function(&function, &options);
        assert_eq!(
            pseudocode.return_type.as_deref(),
            Some(function.return_type.as_str())
        );
        assert_eq!(pseudocode.return_reason, function.return_reason);
        pseudocode.lines[0].text.clone()
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
            without_reason(&emit_function(&function, &Options::default())),
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
            without_reason(&emit_function(&function, &Options::default())),
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
    fn an_architectures_graph_returning_no_value_in_a_valued_function_is_refused() {
        let node = |terminator: Terminator| Node {
            address: 0x100,
            statements: Vec::new(),
            terminator,
        };
        let graph = |return_type: &str| crate::plugin::LiftedGraph {
            return_type: return_type.to_string(),
            params: Vec::new(),
            locals: Vec::new(),
            entry: 0,
            nodes: vec![node(Terminator::Return)],
            frame: Vec::new(),
        };
        let disasm = Disasm {
            file_offset_of_segment: 0,
            instructions: Vec::new(),
        };
        let cfg = ProcedureCfg::default();
        let options = Options::default();
        let error = match lift_graph(graph("int"), &disasm, &cfg, 0x100, "f", &options) {
            Err(error) => error,
            Ok(_) => panic!("a function returning int with no return value lifted"),
        };
        assert!(
            error
                .reason
                .contains("returns no value in a function returning int"),
            "{error:?}"
        );
        let stages = match lift_graph(graph("void"), &disasm, &cfg, 0x100, "f", &options) {
            Ok(stages) => stages,
            Err(error) => panic!("the void function lifts: {error}"),
        };
        assert_eq!(stages.function.return_type, "void");
        assert!(stages.low.is_empty());
        assert_eq!(stages.chains.len(), 1);
    }

    #[test]
    fn setcc_is_the_condition_as_a_byte() {
        // cmp edi, esi; setl al; movzx eax, al; ret
        let text = c(&[0x39, 0xf7, 0x0f, 0x9c, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3]);
        assert!(text.contains("a < b"), "{text}");
    }

    #[test]
    fn setcc_into_a_zeroed_register_is_the_whole_register() {
        // xor eax, eax; cmp edi, esi; setl al; ret — the idiom without movzx.
        let text = c(&[0x31, 0xc0, 0x39, 0xf7, 0x0f, 0x9c, 0xc0, 0xc3]);
        assert!(text.contains("return a < b;"), "{text}");
        // A dec's zero flag is its result's; the zero idiom's carry is
        // clear, so a jb after it never goes.
        // dec edi; jne .two; mov eax, 1; ret; .two: mov eax, 2; ret
        let text = c(&[
            0xff, 0xcf, 0x75, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ]);
        assert!(text.contains("!= 0") || text.contains("== 0"), "{text}");
        // xor eax, eax; jb .two; mov eax, 1; ret; .two: mov eax, 2; ret
        let text = c(&[
            0x31, 0xc0, 0x72, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ]);
        assert!(!text.contains("not lifted"), "{text}");
        // test edi, edi; ja .two: above means not zero.
        let text = c(&[
            0x85, 0xff, 0x77, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ]);
        assert!(text.contains("a != 0") || text.contains("a == 0"), "{text}");
    }

    #[test]
    fn cmovcc_chooses_by_the_condition() {
        // mov eax, edi; cmp edi, esi; cmovl eax, esi; ret
        let text = c(&[0x89, 0xf8, 0x39, 0xf7, 0x0f, 0x4c, 0xc6, 0xc3]);
        assert!(text.contains("return (a < b) ? b : a;"), "{text}");
    }

    #[test]
    fn a_flag_the_producer_did_not_write_is_not_read_from_it() {
        // inc edi; jb .two; mov eax, 1; ret; .two: mov eax, 2; ret — inc
        // leaves the carry, so the jb reads one nothing set.
        let code = [
            0xff, 0xc7, 0x72, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        let reason = refused(&code);
        assert!(
            reason.contains("reads CF that nothing tracked set"),
            "{reason}"
        );
        // The zero flag inc does write reads back as the result's.
        let code = [
            0xff, 0xc7, 0x74, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        let text = c(&code);
        assert!(
            text.contains("(a + 1) == 0") || text.contains("(a + 1) != 0"),
            "{text}"
        );
    }

    #[test]
    fn flags_two_instructions_wrote_are_refused_by_name() {
        // cmp edi, esi; inc edx; jbe .two; …: jbe reads the cmp's carry and
        // the inc's zero flag.
        let code = [
            0x39, 0xf7, 0xff, 0xc2, 0x76, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        let reason = refused(&code);
        assert!(
            reason.contains("reads flags two instructions set"),
            "{reason}"
        );
        assert!(reason.contains("cmp") && reason.contains("inc"), "{reason}");
    }

    #[test]
    fn an_arithmetic_instructions_flags_are_read_from_its_result() {
        // sub edi, esi; jb .two; mov eax, 1; ret; .two: mov eax, 2; ret — the
        // borrow, from the difference and the subtrahend that still stands.
        let code = [
            0x29, 0xf7, 0x72, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        let text = c(&code);
        assert!(
            text.contains("+ b) < (unsigned int)b") || text.contains("+ b) >= (unsigned int)b"),
            "{text}"
        );
        // sub edi, esi; jl: the signed relation of the operands is gone with
        // the destination, so it is refused by name.
        let code = [
            0x29, 0xf7, 0x7c, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        let reason = refused(&code);
        assert!(reason.contains("jl after sub"), "{reason}");
        // add edi, esi; jb: the carry out, the sum below the addend.
        let code = [
            0x01, 0xf7, 0x72, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        let text = c(&code);
        assert!(
            text.contains("< (unsigned int)b") || text.contains(">= (unsigned int)b"),
            "{text}"
        );
        // add edi, edi; jb: neither operand stands.
        let code = [
            0x01, 0xff, 0x72, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        assert!(refused(&code).contains("jb after add"));
    }

    #[test]
    fn the_carry_is_read_back_by_sbb_and_the_bit_by_bt() {
        // cmp edi, esi; sbb eax, eax; ret: eax is 0 minus the borrow.
        let text = c(&[0x39, 0xf7, 0x19, 0xc0, 0xc3]);
        assert!(
            text.contains("0 - ((unsigned int)a < (unsigned int)b)"),
            "{text}"
        );
        // bt edi, 3; jb .two; mov eax, 1; ret; .two: mov eax, 2; ret
        let code = [
            0x0f, 0xba, 0xe7, 0x03, 0x72, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ];
        let text = c(&code);
        assert!(text.contains("(a >> 3) & 1"), "{text}");
        // neg edi; mov eax, edi; ret
        let text = c(&[0xf7, 0xdf, 0x89, 0xf8, 0xc3]);
        assert!(text.contains("0 - a"), "{text}");
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
        // Nothing in the image calls f, and f's own code never touches the
        // result: it is a callee's leftover, and dead.
        assert_eq!(c(&code), "void f(int a)\n{\n  f(a, 3);\n  return;\n}");
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
        assert_eq!(c(&code), "void f(void)\n{\n  sub_4000(1);\n  return;\n}");
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
        // mov eax, edi; jmp rax: rax holds a parameter, not a function.
        assert_eq!(
            refused(&[0x89, 0xf8, 0xff, 0xe0]),
            "not lifted yet: an indirect jump at 0x1002"
        );
        // mov eax, edi; ud2
        assert_eq!(
            refused(&[0x89, 0xf8, 0x0f, 0x0b]),
            "not lifted yet: the block ends in ud2"
        );
        assert_eq!(refused(&[]), "not lifted yet: no code at 0x1000");
    }

    // ---- tail calls and thunks ---------------------------------------------

    #[test]
    fn a_jmp_to_another_function_is_a_tail_call() {
        // mov edi, 5; jmp g: the jmp is at 0x1005, so 0x3000 is 0x1ff6 on.
        // The jump stands for `call g; ret`. With no caller in the image,
        // g's result is a leftover nothing reads, so nothing is returned;
        // a caller that reads it makes it `return g(5);` (see the tests of
        // the return decision).
        assert_eq!(
            c(&[0xbf, 5, 0, 0, 0, 0xe9, 0xf6, 0x1f, 0x00, 0x00]),
            "void f(void)\n{\n  g(5);\n  return;\n}"
        );
        // mov edi, esi; jmp g: as at a call, every argument register the
        // state holds is passed, and reading esi put the parameter there.
        assert_eq!(
            c(&[0x89, 0xf7, 0xe9, 0xf9, 0x1f, 0x00, 0x00]),
            "void f(long a, int b)\n{\n  g(b, b);\n  return;\n}"
        );
        // push rbp; mov rbp, rsp; pop rbp; jmp g: the frame is torn down, so
        // the stack is back where it was.
        let function =
            lift(&[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xe9, 0xf6, 0x1f, 0x00, 0x00]).expect("lifts");
        assert_eq!(
            without_reason(&emit_function(&function, &Options::default())),
            "void f(void)\n{\n  g();\n  return;\n}"
        );
        assert_eq!(function.thunk, None, "a frame is a body of its own");
        let ret = function.body.last().expect("the return");
        assert!(ret.addresses.contains(&0x1005), "the jmp is the return's");
    }

    #[test]
    fn a_jmp_through_a_got_slot_is_a_tail_call_to_the_import() {
        // mov edi, 7; jmp [rip+0x2ff5]: the jmp is at 0x1005 and 6 bytes
        // long, so it reads 0x4000, the slot the image relocates to puts.
        assert_eq!(
            c_with_image(&[0xbf, 7, 0, 0, 0, 0xff, 0x25, 0xf5, 0x2f, 0x00, 0x00]),
            "void f(void)\n{\n  puts(7);\n  return;\n}"
        );
        // The plain names know no slot: the jump goes through memory the
        // lifter cannot name.
        assert_eq!(
            c(&[0xbf, 7, 0, 0, 0, 0xff, 0x25, 0xf5, 0x2f, 0x00, 0x00]),
            "not lifted yet: an indirect jump at 0x1005"
        );
    }

    #[test]
    fn a_jmp_through_a_register_loaded_from_a_got_slot_is_a_tail_call() {
        // mov rax, [rip+0x2ff9]; jmp rax: the mov is 7 bytes, so it loads
        // 0x4000, the slot of puts; what rax holds is that function.
        assert_eq!(
            c_with_image(&[0x48, 0x8b, 0x05, 0xf9, 0x2f, 0x00, 0x00, 0xff, 0xe0]),
            "void f(void)\n{\n  puts();\n  return;\n}"
        );
    }

    #[test]
    fn a_conditional_tail_call_through_a_register_is_a_guard() {
        // mov rax, [rip+0x2ff9]; test rax, rax; je .ret; jmp rax; .ret: ret —
        // the shape of the glibc start-up glue: call the weak import if it
        // is linked. The path that does not jump returns rax, which is the
        // function it tested — a value of the function's own, so the tail
        // call's result is handed on with it; that arm never falls through,
        // so it is the guard.
        let code = [
            0x48, 0x8b, 0x05, 0xf9, 0x2f, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x02, 0xff, 0xe0,
            0xc3,
        ];
        assert_eq!(
            c_with_image(&code),
            "long f(void)\n{\n  if (puts == 0) {\n    return puts;\n  }\n  return puts();\n}"
        );
    }

    #[test]
    fn a_load_from_a_got_slot_is_the_import_and_its_address_is_an_address() {
        // mov rax, [rip+0x2ff9]; ret: the slot holds the address of puts.
        assert_eq!(
            c_with_image(&[0x48, 0x8b, 0x05, 0xf9, 0x2f, 0x00, 0x00, 0xc3]),
            "long f(void)\n{\n  return puts;\n}"
        );
        // mov eax, [rip+0x2ffa]; ret: half a pointer is not the function.
        assert_eq!(
            c_with_image(&[0x8b, 0x05, 0xfa, 0x2f, 0x00, 0x00, 0xc3]),
            "int f(void)\n{\n  return *(int *)0x4000;\n}"
        );
        // lea rax, [rip+0x2ff9]; ret: the slot's own address.
        assert_eq!(
            c_with_image(&[0x48, 0x8d, 0x05, 0xf9, 0x2f, 0x00, 0x00, 0xc3]),
            "long f(void)\n{\n  return 0x4000;\n}"
        );
    }

    #[test]
    fn a_function_that_is_only_a_jmp_is_a_thunk() {
        // endbr64; jmp g: a forwarding stub.
        let function =
            lift(&[0xf3, 0x0f, 0x1e, 0xfa, 0xe9, 0xf7, 0x1f, 0x00, 0x00]).expect("lifts");
        assert_eq!(function.thunk.as_deref(), Some("g"));
        assert!(function.body.is_empty() && function.params.is_empty());
        let pseudocode = emit_function(&function, &Options::default());
        assert_eq!(pseudocode.text(), "// thunk for g");
        assert_eq!(
            pseudocode.lines[0].addresses,
            vec![0x1000, 0x1004],
            "the one line stands for every instruction"
        );

        // endbr64; bnd jmp [rip+0x2ff5]; nop: a PLT stub, through the slot
        // of puts. The jmp is at 0x1004 and 7 bytes long with its prefix.
        let code = [
            0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25, 0xf5, 0x2f, 0x00, 0x00, 0x90,
        ];
        assert_eq!(c_with_image(&code), "// thunk for puts");

        // jmp g alone is a thunk too; mov edi, 1; jmp g is not.
        assert_eq!(c(&[0xe9, 0xfb, 0x1f, 0x00, 0x00]), "// thunk for g");
        assert_eq!(
            c(&[0xbf, 1, 0, 0, 0, 0xe9, 0xf6, 0x1f, 0x00, 0x00]),
            "void f(void)\n{\n  g(1);\n  return;\n}"
        );
    }

    #[test]
    fn a_jmp_that_leaves_with_the_stack_unbalanced_or_to_nowhere_is_refused() {
        // push rdi; jmp g
        assert_eq!(
            refused(&[0x57, 0xe9, 0xfa, 0x1f, 0x00, 0x00]),
            "not lifted yet: the stack is not balanced at the jmp at 0x1001"
        );
        // jmp 0x2500: no function the names know, and no code there.
        assert_eq!(
            refused(&[0xe9, 0xfb, 0x14, 0x00, 0x00]),
            "not lifted yet: jumps to 0x2500"
        );
        // mov rax, [rip+0x2ff9]; jmp rax, with names that know no slot: rax
        // holds a load from an address, not a function.
        assert_eq!(
            refused(&[0x48, 0x8b, 0x05, 0xf9, 0x2f, 0x00, 0x00, 0xff, 0xe0]),
            "not lifted yet: an indirect jump at 0x1007"
        );
    }

    #[test]
    fn a_jmp_within_the_function_is_still_an_edge() {
        // jmp .ret; .ret: mov eax, edi; ret — a jump forward to code of the
        // function's own, which no name claims.
        assert_eq!(
            c(&[0xeb, 0x00, 0x89, 0xf8, 0xc3]),
            "int f(int a)\n{\n  return a;\n}"
        );
    }

    #[test]
    fn the_tail_calls_option_refuses_the_jump_by_callee() {
        // mov edi, esi; jmp g
        assert_eq!(
            c_with(
                &[0x89, 0xf7, 0xe9, 0xf9, 0x1f, 0x00, 0x00],
                &names,
                &[("tail-calls", "refuse")]
            ),
            "not lifted yet: a tail call to g at 0x1002"
        );
        // endbr64; jmp g: a thunk is a tail call too.
        assert_eq!(
            c_with(
                &[0xf3, 0x0f, 0x1e, 0xfa, 0xe9, 0xf7, 0x1f, 0x00, 0x00],
                &names,
                &[("tail-calls", "refuse")]
            ),
            "not lifted yet: a tail call to g at 0x1004"
        );
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
    fn an_indirect_call_goes_through_its_value_or_is_refused() {
        // call rdi; ret: the call goes through the parameter, which the
        // first argument register still holds, and its result is nobody's.
        assert_eq!(
            c(&[0xff, 0xd7, 0xc3]),
            "void f(long a)\n{\n  a(a);\n  return;\n}"
        );
        assert_eq!(
            c_with(&[0xff, 0xd7, 0xc3], &names, &[("indirect-calls", "refuse")]),
            "not lifted yet: an indirect call"
        );
    }

    /// Symbols that name the control-flow guard's pointers at 0x4000 (the
    /// dispatcher) and 0x4008 (the check), and the function `add` at 0x2000.
    struct Guarded;

    impl Symbols for Guarded {
        fn function_name(&self, address: u64) -> Option<String> {
            (address == 0x2000).then(|| "add".to_string())
        }

        fn pointee(&self, address: u64) -> Option<Pointee> {
            match address {
                0x4000 => Some(Pointee::Data("__guard_dispatch_icall_fptr".to_string())),
                0x4008 => Some(Pointee::Data("__guard_check_icall_fptr".to_string())),
                _ => None,
            }
        }
    }

    #[test]
    fn a_control_flow_guard_dispatch_is_the_call_it_guards() {
        // mov rax, rdi; call [rip+disp → 0x4000]; ret: the call goes to the
        // function in rax, the parameter.
        let through = c_with(
            &[0x48, 0x89, 0xf8, 0xff, 0x15, 0xf7, 0x2f, 0x00, 0x00, 0xc3],
            &Guarded,
            &[],
        );
        assert_eq!(through, "void f(long a)\n{\n  a(a);\n  return;\n}");
        // lea rax, [rip+disp → 0x2000]; mov edi, 3; call [0x4000]; ret: the
        // function in rax is named, and called outright.
        let named = c_with(
            &[
                0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0xbf, 0x03, 0x00, 0x00, 0x00, 0xff, 0x15,
                0xee, 0x2f, 0x00, 0x00, 0xc3,
            ],
            &Guarded,
            &[],
        );
        assert!(named.contains("  add(3);"), "{named}");
        // mov r8, [0x4000]; mov rax, rdi; jmp r8: the dispatcher loaded into
        // a register and jumped through is a tail call through rax.
        let tail = c_with(
            &[
                0x4c, 0x8b, 0x05, 0xf9, 0x2f, 0x00, 0x00, 0x48, 0x89, 0xf8, 0x41, 0xff, 0xe0,
            ],
            &Guarded,
            &[],
        );
        assert_eq!(tail, "void f(long a)\n{\n  a(a);\n  return;\n}");
        // mov rcx, rdi; call [0x4008]; call rcx; ret: the check validates
        // rcx and is dropped; the call through rcx stands.
        let checked = c_with(
            &[
                0x48, 0x89, 0xf9, 0xff, 0x15, 0xff, 0x2f, 0x00, 0x00, 0xff, 0xd1, 0xc3,
            ],
            &Guarded,
            &[],
        );
        assert_eq!(checked, "void f(long a)\n{\n  a(a);\n  return;\n}");
        // A `rax` that holds the dispatcher itself goes nowhere: refused,
        // not followed round. mov rax, [0x4000]; call rax; ret — and the
        // same through the slot.
        assert_eq!(
            c_with(
                &[0x48, 0x8b, 0x05, 0xf9, 0x2f, 0x00, 0x00, 0xff, 0xd0, 0xc3],
                &Guarded,
                &[]
            ),
            "not lifted yet: an indirect call"
        );
        assert_eq!(
            c_with(
                &[
                    0x48, 0x8b, 0x05, 0xf9, 0x2f, 0x00, 0x00, 0xff, 0x15, 0xf3, 0x2f, 0x00, 0x00,
                    0xc3
                ],
                &Guarded,
                &[]
            ),
            "not lifted yet: an indirect call"
        );
        // A jump through the dispatcher to a `rax` the lift does not know
        // is refused as the jump it is. mov rax, [0x4008]; jmp [0x4000]
        assert_eq!(
            c_with(
                &[0x48, 0x8b, 0x05, 0x01, 0x30, 0x00, 0x00, 0xff, 0x25, 0xf3, 0x2f, 0x00, 0x00],
                &Guarded,
                &[]
            ),
            "not lifted yet: an indirect jump at 0x1007"
        );
        // Under `indirect-calls refuse` the dispatch to a parameter is refused
        // as the indirect call it is, and the named target still goes.
        let refused = c_with(
            &[0x48, 0x89, 0xf8, 0xff, 0x15, 0xf7, 0x2f, 0x00, 0x00, 0xc3],
            &Guarded,
            &[("indirect-calls", "refuse")],
        );
        assert_eq!(refused, "not lifted yet: an indirect call");
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
            without_reason(&emit_function(&function, &Options::default())),
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
            without_reason(&emit_function(&function, &Options::default())),
            "int f(void)\n{\n  return f(1);\n}"
        );

        // call f; call g; ret: three blocks, two calls, the second's
        // result left in rax — a leftover nobody in the image reads.
        let code = [
            0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xe8, 0xf6, 0x1f, 0x00, 0x00, 0xc3,
        ];
        let (cfg, lifted) = lift_cfg(&code, Bitness::Bits64);
        assert_eq!(cfg.blocks.len(), 3);
        assert_eq!(
            without_reason(&emit_function(
                &lifted.expect("the chain lifts"),
                &Options::default()
            )),
            "void f(void)\n{\n  f();\n  g();\n  return;\n}"
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
            without_reason(&emit_function(&function, &Options::default())),
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
            without_reason(&emit_function(&lifted.expect("lifts"), &Options::default())),
            "int f(int a)\n{\n  return a;\n}"
        );
        // jmp +0; ret
        let (cfg, lifted) = lift_cfg(&[0xeb, 0x00, 0xc3], Bitness::Bits64);
        assert_eq!(cfg.blocks.len(), 2);
        assert_eq!(
            without_reason(&emit_function(&lifted.expect("lifts"), &Options::default())),
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
            without_reason(&emit_function(&function, &Options::default())),
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
        assert_eq!(
            c(&code),
            "// does not return\nvoid f(void)\n{\n  f();\n  while (1) {\n  }\n}"
        );
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
            "not lifted yet: the je at 0x1002 reads ZF that nothing tracked set"
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

    /// An image that knows a string, a piece of data, a function and the
    /// GOT slot of an import.
    struct Image;

    impl Symbols for Image {
        fn function_name(&self, address: u64) -> Option<String> {
            names(address)
        }

        fn pointee(&self, address: u64) -> Option<Pointee> {
            match address {
                0x2007 => Some(Pointee::String("%ld\n".into())),
                0x3007 => Some(Pointee::Data("counter".into())),
                0x3017 => Some(Pointee::Data("limit".into())),
                0x2000 => Some(Pointee::Function("f".into())),
                0x4000 => Some(Pointee::Import("puts".into())),
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
            "void f(void)\n{\n  f(\"%ld\\n\");\n  return;\n}"
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
        // The reason comment opens the function, and came from no
        // instruction; the signature follows it.
        assert!(pseudocode.lines[0].text.starts_with("// returns int: "));
        assert_eq!(pseudocode.lines[1].addresses, vec![0x1000, 0x1001, 0x1006]);
        assert_eq!(pseudocode.lines[3].addresses, vec![0x1004, 0x1007]);
        assert_eq!(
            pseudocode
                .line_addresses()
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![1, 3],
            "the comment and the braces come from no instruction"
        );
    }

    // ---- conditions over addresses -----------------------------------------

    /// lea rdi, [rip+0x2000]; lea rax, [rip+disp]; cmp rax, rdi; je .ret;
    /// mov rax, 1; .ret: ret. The first lea names 0x3007, `counter`; the
    /// second names 0x100e + disp. The paths into the ret leave rax
    /// different, so the join names it, and the entry path assigns it the
    /// address after the compare.
    fn compare_addresses(disp: u32) -> Vec<u8> {
        let [d0, d1, d2, d3] = disp.to_le_bytes();
        vec![
            0x48, 0x8d, 0x3d, 0x00, 0x20, 0x00, 0x00, 0x48, 0x8d, 0x05, d0, d1, d2, d3, 0x48, 0x39,
            0xf8, 0x74, 0x07, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xc3,
        ]
    }

    #[test]
    fn a_comparison_of_two_addresses_prints_the_addresses() {
        // The second lea names 0x3017, `limit`. The operands are constants
        // at the compare, so the condition keeps them: the join's `rax`
        // stands for the register after the assignment, not for the
        // address `rdi` held.
        let code = compare_addresses(0x2009);
        assert_eq!(
            c_with_image(&code),
            "long f(void)\n\
             {\n\
             \x20 long rax;\n\
             \n\
             \x20 rax = &limit;\n\
             \x20 if (&limit != &counter) {\n\
             \x20   rax = 1;\n\
             \x20 }\n\
             \x20 return rax;\n\
             }"
        );
    }

    #[test]
    fn a_comparison_of_an_address_with_itself_is_a_constant_condition() {
        // The second lea names 0x3007 too: `&counter != &counter` can only
        // go one way, so the condition is the constant, and the comment
        // says what the bytes compared.
        let code = compare_addresses(0x1ff9);
        assert_eq!(
            c_with_image(&code),
            "long f(void)\n\
             {\n\
             \x20 long rax;\n\
             \n\
             \x20 rax = &counter;\n\
             \x20 if (0) { // constant: &counter != &counter\n\
             \x20   rax = 1;\n\
             \x20 }\n\
             \x20 return rax;\n\
             }"
        );

        // `constant-conditions expression` prints the comparison instead.
        let text = c_with(&code, &Image, &[("constant-conditions", "expression")]);
        assert!(
            text.contains("  rax = &counter;\n  if (&counter != &counter) {\n"),
            "{text}"
        );
    }

    #[test]
    fn a_value_compared_with_itself_is_a_constant_condition() {
        // cmp rdi, rdi; jne .zero; mov eax, 1; ret; .zero: xor eax, eax;
        // ret: the parameter against itself can only go one way.
        let code = [
            0x48, 0x39, 0xff, 0x75, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0, 0xc3,
        ];
        assert_eq!(
            c(&code),
            "int f(long a)\n\
             {\n\
             \x20 if (0) { // constant: a != a\n\
             \x20   return 0;\n\
             \x20 }\n\
             \x20 return 1;\n\
             }"
        );
    }

    #[test]
    fn a_computed_operand_still_reads_the_variable_the_join_names() {
        // The sample's deregister_tm_clones, against the test image:
        // lea rdi, [counter]; lea rax, [counter]; cmp rax, rdi; je .ret;
        // mov rax, [puts@GOT]; test rax, rax; je .ret; jmp rax; .ret: ret.
        // The addresses are constants at the compare and keep their
        // expressions; the name loaded from the slot is a value, so the
        // guard reads the variable the join names, `rax != 0`, as before.
        let code = [
            0x48, 0x8d, 0x3d, 0x00, 0x20, 0x00, 0x00, 0x48, 0x8d, 0x05, 0xf9, 0x1f, 0x00, 0x00,
            0x48, 0x39, 0xf8, 0x74, 0x0e, 0x48, 0x8b, 0x05, 0xe6, 0x2f, 0x00, 0x00, 0x48, 0x85,
            0xc0, 0x74, 0x02, 0xff, 0xe0, 0xc3,
        ];
        assert_eq!(
            c_with_image(&code),
            "long f(void)\n\
             {\n\
             \x20 long rax;\n\
             \n\
             \x20 rax = &counter;\n\
             \x20 if (0) { // constant: &counter != &counter\n\
             \x20   rax = puts;\n\
             \x20   if (rax != 0) {\n\
             \x20     return puts(&counter);\n\
             \x20   }\n\
             \x20 }\n\
             \x20 return rax;\n\
             }"
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

    // ---- the return decision ----------------------------------------------

    /// Symbols under which the function being lifted, at [`BASE`], has the
    /// given call sites, and nothing else has any.
    struct Callers(Vec<CallSiteUse>);

    impl Symbols for Callers {
        fn function_name(&self, address: u64) -> Option<String> {
            names(address)
        }

        fn result_uses(&self, address: u64) -> Vec<CallSiteUse> {
            if address == BASE {
                self.0.clone()
            } else {
                Vec::new()
            }
        }
    }

    /// A call site in the caller `name` at `caller`, with what it does with
    /// the result.
    fn site(caller: u64, name: &str, result: ResultUse) -> CallSiteUse {
        CallSiteUse {
            caller,
            caller_name: name.to_string(),
            site: caller + 0x10,
            result,
        }
    }

    /// `call f; ret`: f's result exactly as the call left it.
    const CALL_F_RET: [u8; 6] = [0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xc3];

    #[test]
    fn a_caller_that_reads_the_result_makes_it_returned_at_the_width_read() {
        // The leftover of f is returned because main reads it, as eax.
        let callers = Callers(vec![site(0x5000, "main", ResultUse::Read { bits: 32 })]);
        assert_eq!(
            c_with(&CALL_F_RET, &callers, &[]),
            "int f(void)\n{\n  return f();\n}"
        );
        assert_eq!(
            decided(&CALL_F_RET, &callers, &[]),
            "// returns int: main reads eax after the call"
        );

        // The widest read decides the width, and names the reader; a
        // caller that discards it has no say.
        let callers = Callers(vec![
            site(0x5000, "main", ResultUse::Read { bits: 32 }),
            site(0x6000, "h", ResultUse::Read { bits: 64 }),
            site(0x7000, "k", ResultUse::Killed),
        ]);
        assert_eq!(
            c_with(&CALL_F_RET, &callers, &[]),
            "long f(void)\n{\n  return f();\n}"
        );
        assert_eq!(
            decided(&CALL_F_RET, &callers, &[]),
            "// returns long: h reads rax after the call"
        );

        // mov rax, rdi; ret: a value written wider than its callers read
        // is returned at the width read, cast.
        let code = [0x48, 0x89, 0xf8, 0xc3];
        let callers = Callers(vec![site(0x5000, "main", ResultUse::Read { bits: 32 })]);
        assert_eq!(
            c_with(&code, &callers, &[]),
            "int f(long a)\n{\n  return (int)a;\n}"
        );

        // A tail call whose result a caller reads is the return it stands
        // for: mov edi, 5; jmp g.
        let code = [0xbf, 5, 0, 0, 0, 0xe9, 0xf6, 0x1f, 0x00, 0x00];
        assert_eq!(
            c_with(&code, &callers, &[]),
            "int f(void)\n{\n  return g(5);\n}"
        );
    }

    #[test]
    fn callers_that_all_discard_the_result_make_the_function_void() {
        // mov eax, edi; ret: a value the function computed, read by nobody.
        let code = [0x89, 0xf8, 0xc3];
        let callers = Callers(vec![
            site(0x5000, "main", ResultUse::Killed),
            site(0x6000, "h", ResultUse::Killed),
        ]);
        assert_eq!(
            c_with(&code, &callers, &[]),
            "void f(int a)\n{\n  return;\n}"
        );
        assert_eq!(
            decided(&code, &callers, &[]),
            "// void: no caller reads the result"
        );

        // A tail call, likewise: the callee is called, and nothing returned.
        let code = [0xbf, 5, 0, 0, 0, 0xe9, 0xf6, 0x1f, 0x00, 0x00];
        assert_eq!(
            c_with(&code, &callers, &[]),
            "void f(void)\n{\n  g(5);\n  return;\n}"
        );

        // Under `return-liveness presence` the callers are not asked, and a
        // written rax is returned as it always was.
        let presence = [("return-liveness", "presence")];
        assert_eq!(
            c_with(&[0x89, 0xf8, 0xc3], &callers, &presence),
            "int f(int a)\n{\n  return a;\n}"
        );
        assert_eq!(
            decided(&[0x89, 0xf8, 0xc3], &callers, &presence),
            "// returns int: rax holds a value at the ret"
        );
        assert_eq!(
            c_with(&CALL_F_RET, &names, &presence),
            "long f(void)\n{\n  return f();\n}"
        );
    }

    #[test]
    fn a_caller_that_returns_the_result_passes_the_question_to_its_callers() {
        // f's caller g carries the result untouched to its own ret, and g's
        // caller main reads it as eax: f returns an int, through g.
        struct Chain;
        impl Symbols for Chain {
            fn function_name(&self, address: u64) -> Option<String> {
                names(address)
            }
            fn result_uses(&self, address: u64) -> Vec<CallSiteUse> {
                match address {
                    BASE => vec![site(0x3000, "g", ResultUse::Returned)],
                    0x3000 => vec![site(0x5000, "main", ResultUse::Read { bits: 32 })],
                    _ => Vec::new(),
                }
            }
        }
        let code = [0x89, 0xf8, 0xc3];
        assert_eq!(
            c_with(&code, &Chain, &[]),
            "int f(int a)\n{\n  return a;\n}"
        );
        assert_eq!(
            decided(&code, &Chain, &[]),
            "// returns int: g returns it, and main reads eax after the call"
        );

        // A chain that ends in a function with no caller reads nothing, and
        // a cycle of returning callers is followed once.
        struct Cycle;
        impl Symbols for Cycle {
            fn function_name(&self, address: u64) -> Option<String> {
                names(address)
            }
            fn result_uses(&self, address: u64) -> Vec<CallSiteUse> {
                match address {
                    BASE => vec![site(0x3000, "g", ResultUse::Returned)],
                    0x3000 => vec![
                        site(BASE, "f", ResultUse::Returned),
                        site(0x2000, "f2", ResultUse::Returned),
                    ],
                    _ => Vec::new(),
                }
            }
        }
        assert_eq!(c_with(&code, &Cycle, &[]), "void f(int a)\n{\n  return;\n}");
        assert_eq!(
            decided(&code, &Cycle, &[]),
            "// void: no caller reads the result"
        );
    }

    #[test]
    fn with_no_caller_a_callees_leftover_is_dead_and_an_own_value_is_returned() {
        // call f; ret: nothing of the function's own went into rax.
        assert_eq!(c(&CALL_F_RET), "void f(void)\n{\n  f();\n  return;\n}");
        assert_eq!(
            decided(&CALL_F_RET, &names, &[]),
            "// void: no caller in the image, and rax at the ret holds only f's result, \
             which nothing reads"
        );

        // call f; mov eax, eax; ret: the mov is the function's own write.
        let code = [0xe8, 0xfb, 0x0f, 0x00, 0x00, 0x89, 0xc0, 0xc3];
        assert_eq!(c(&code), "int f(void)\n{\n  return f();\n}");
        assert_eq!(
            decided(&code, &names, &[]),
            "// returns int: no caller in the image, and the function writes rax itself \
             before the ret"
        );

        // call f; cmp eax, 1; jne .a; call g; ret; .a: ret: f's result is
        // read by the function itself — the branch tests it — so it is not
        // a dead leftover, and is returned at the width read; g's, read by
        // nothing, is handed on at that width on the other path.
        let code = [
            0xe8, 0xfb, 0x0f, 0x00, 0x00, 0x83, 0xf8, 0x01, 0x75, 0x06, 0xe8, 0xf1, 0x1f, 0x00,
            0x00, 0xc3, 0xc3,
        ];
        assert_eq!(
            c(&code),
            "int f(void)\n{\n  int v1;\n\n  v1 = f();\n  if (v1 != 1) {\n    return v1;\n  }\n  \
             return g();\n}"
        );

        // A function that never writes rax says so.
        assert_eq!(
            decided(&[0x90, 0xc3], &names, &[]),
            "// void: no ret has a value in rax"
        );
    }

    #[test]
    fn the_rets_must_agree_on_the_live_decisions() {
        // The shape of __do_global_dtors_aux: cmp edi, 0; jne .done; call f;
        // ret; .done: ret. One path leaves f's dead result, the other
        // nothing: void, not a disagreement.
        let dtors = [
            0x83, 0xff, 0x00, 0x75, 0x06, 0xe8, 0xf6, 0x0f, 0x00, 0x00, 0xc3, 0xc3,
        ];
        assert_eq!(
            c(&dtors),
            "void f(int a)\n{\n  if (a != 0) {\n    return;\n  }\n  f(a);\n  return;\n}"
        );
        assert_eq!(
            decided(&dtors, &names, &[]),
            "// void: no caller in the image, and rax at the ret holds only f's result, \
             which nothing reads"
        );
        // Under `presence` it is the disagreement it always was.
        assert_eq!(
            c_with(&dtors, &names, &[("return-liveness", "presence")]),
            "not lifted yet: returns a value at one ret and nothing at another"
        );
        // And with a caller that reads the result, the path with nothing in
        // rax is a disagreement.
        let callers = Callers(vec![site(0x5000, "main", ResultUse::Read { bits: 32 })]);
        assert_eq!(
            c_with(&dtors, &callers, &[]),
            "not lifted yet: returns a value at one ret and nothing at another"
        );

        // cmp edi, 0; jne .done; mov eax, 1; ret; .done: ret: an own value
        // on one path and nothing on the other is refused.
        let code = [0x83, 0xff, 0x00, 0x75, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xc3];
        assert_eq!(
            c(&code),
            "not lifted yet: returns a value at one ret and nothing at another"
        );
        // cmp edi, 0; jne .done; mov eax, 1; ret; .done: mov rax, rdi; ret:
        // own values of two widths are refused.
        let code = [
            0x83, 0xff, 0x00, 0x75, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0x48, 0x89, 0xf8, 0xc3,
        ];
        assert_eq!(
            c(&code),
            "not lifted yet: returns 64 bits at one ret and 32 at another"
        );
        // cmp rdi, 0; jne .call; mov rax, rdi; ret; .call: call f; ret: an
        // own value on one path lets the other hand on f's result.
        let code = [
            0x48, 0x83, 0xff, 0x00, 0x75, 0x04, 0x48, 0x89, 0xf8, 0xc3, 0xe8, 0xf1, 0x0f, 0x00,
            0x00, 0xc3,
        ];
        assert_eq!(
            c(&code),
            "long f(long a)\n{\n  if (a != 0) {\n    return f(a);\n  }\n  return a;\n}"
        );
    }

    #[test]
    fn a_register_a_call_clobbered_on_one_path_is_not_a_parameter_after_the_join() {
        // test edi, edi; je .skip; call f; .skip: ret: the call clobbers the
        // argument registers on one path, and the other never touched them.
        // Nothing reads them after the join, so they are not parameters —
        // only edi, which the test read, is one. The join leaves rax as f's
        // result on one path and nothing on the other: no value of the
        // function's own, so the ret returns nothing.
        let code = [0x85, 0xff, 0x74, 0x05, 0xe8, 0xf7, 0x0f, 0x00, 0x00, 0xc3];
        assert_eq!(
            c(&code),
            "void f(int a)\n{\n  if (a != 0) {\n    f(a);\n  }\n  return;\n}"
        );
        assert_eq!(
            decided(&code, &names, &[]),
            "// void: no caller in the image, and rax at the ret holds only f's result, \
             which nothing reads"
        );
        // A caller that reads the result asks for a value one path does not
        // have, and that is refused.
        let callers = Callers(vec![site(0x5000, "main", ResultUse::Read { bits: 32 })]);
        assert_eq!(
            c_with(&code, &callers, &[]),
            "not lifted yet: f's result on one path and nothing on another"
        );
        // Under presence the merge is unknown, as it always was.
        assert_eq!(
            c_with(&code, &names, &[("return-liveness", "presence")]),
            "not lifted yet: f's result on one path and nothing on another"
        );
    }

    #[test]
    fn rep_movs_and_rep_stos_are_the_builtins_they_stand_for() {
        // mov rcx, rdx; rep movsb; ret
        let copy = c(&[0x48, 0x89, 0xd1, 0xf3, 0xa4, 0xc3]);
        assert!(copy.contains("  __builtin_memcpy(a, b, c);"), "{copy}");
        // mov rcx, rdx; mov eax, esi; rep stosb; ret: the byte of eax.
        let fill = c(&[0x48, 0x89, 0xd1, 0x89, 0xf0, 0xf3, 0xaa, 0xc3]);
        assert!(
            fill.contains("  __builtin_memset(a, (char)b, c);"),
            "{fill}"
        );
        // mov rcx, rdx; mov rax, rsi; rep stosq; ret: eight bytes an element.
        let words = c(&[0x48, 0x89, 0xd1, 0x48, 0x89, 0xf0, 0xf3, 0x48, 0xab, 0xc3]);
        assert!(
            words.contains("  __builtin_memset(a, b, c * 8);"),
            "{words}"
        );
        // After the copy rdi is past it: mov rcx, rdx; rep movsb; mov rax, rdi; ret
        let after = c(&[0x48, 0x89, 0xd1, 0xf3, 0xa4, 0x48, 0x89, 0xf8, 0xc3]);
        assert!(
            after.contains("  __builtin_memcpy(a, b, c);\n  return a + c;"),
            "{after}"
        );
        // Without the prefix the instruction moves one element, and is not
        // read; the SSE movsd is a register move the lifter does not know.
        assert_eq!(refused(&[0xa4, 0xc3]), "not lifted yet: movsb without rep");
        assert_eq!(
            refused(&[0xf2, 0x0f, 0x10, 0xc1, 0xc3]),
            "not lifted yet: movsd"
        );
    }

    #[test]
    fn a_string_on_the_stack_is_one_variables_run_and_the_other_forms_are_read() {
        // Byte by byte: sub rsp, 16; mov byte [rsp], 'h'; mov byte [rsp+1],
        // 'i'; mov byte [rsp+2], 0; lea rax, [rsp]; add rsp, 16; ret
        let bytes = c(&[
            0x48, 0x83, 0xec, 0x10, 0xc6, 0x04, 0x24, 0x68, 0xc6, 0x44, 0x24, 0x01, 0x69, 0xc6,
            0x44, 0x24, 0x02, 0x00, 0x48, 0x8d, 0x04, 0x24, 0x48, 0x83, 0xc4, 0x10, 0xc3,
        ]);
        assert!(
            bytes.contains("  __builtin_strcpy(&local_10, \"hi\");\n  return &local_10;"),
            "{bytes}"
        );
        // Two variables of their own, each with its address taken: a store
        // to the second is its own, not the first's string. sub rsp, 16;
        // mov word [rsp], 'hi'; mov word [rsp+2], 0; lea rdi, [rsp]; lea rsi,
        // [rsp+2]; call +0x100; add rsp, 16; ret
        let two = c(&[
            0x48, 0x83, 0xec, 0x10, 0x66, 0xc7, 0x04, 0x24, 0x68, 0x69, 0x66, 0xc7, 0x44, 0x24,
            0x02, 0x00, 0x00, 0x48, 0x8d, 0x3c, 0x24, 0x48, 0x8d, 0x74, 0x24, 0x02, 0xe8, 0x00,
            0x01, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x10, 0xc3,
        ]);
        assert!(two.contains("local_e = 0;"), "{two}");
        assert!(!two.contains("__builtin_"), "{two}");
        // A store into two variables at once is not told apart: sub rsp, 32;
        // mov qword [rsp+4], 7; lea rdi, [rsp]; lea rsi, [rsp+8]; call; add
        // rsp, 32; ret
        let straddle = c(&[
            0x48, 0x83, 0xec, 0x20, 0x48, 0xc7, 0x44, 0x24, 0x04, 0x07, 0x00, 0x00, 0x00, 0x48,
            0x8d, 0x3c, 0x24, 0x48, 0x8d, 0x74, 0x24, 0x08, 0xe8, 0x00, 0x01, 0x00, 0x00, 0x48,
            0x83, 0xc4, 0x20, 0xc3,
        ]);
        assert_eq!(straddle, "not lifted yet: a partial write to local_20");
    }

    #[test]
    fn a_fill_of_the_frame_forgets_the_slots_it_writes() {
        // sub rsp, 32; mov qword [rsp+16], 5; lea rdi, [rsp]; mov ecx, 8; xor
        // eax, eax; rep stosq; mov rax, [rsp+16]; add rsp, 32; ret: the 5 is
        // written over, and the count folds into the byte count.
        let text = c(&[
            0x48, 0x83, 0xec, 0x20, 0x48, 0xc7, 0x44, 0x24, 0x10, 0x05, 0x00, 0x00, 0x00, 0x48,
            0x8d, 0x3c, 0x24, 0xb9, 0x08, 0x00, 0x00, 0x00, 0x31, 0xc0, 0xf3, 0x48, 0xab, 0x48,
            0x8b, 0x44, 0x24, 0x10, 0x48, 0x83, 0xc4, 0x20, 0xc3,
        ]);
        assert!(
            text.contains("__builtin_memset(&local_20, 0, 0x40);"),
            "{text}"
        );
        assert!(!text.contains("return 5;"), "{text}");
        // The SSE store `movsd [rdi], xmm0` shares the mnemonic and is not a
        // string operation.
        assert_eq!(
            refused(&[0xf2, 0x0f, 0x11, 0x07, 0xc3]),
            "not lifted yet: movsd"
        );
    }

    #[test]
    fn a_run_of_field_stores_is_a_struct_initializer() {
        // mov [rdi], esi; mov dword [rdi+4], 2; mov qword [rdi+8], 7; ret
        let code = [
            0x89, 0x37, 0xc7, 0x47, 0x04, 0x02, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x47, 0x08, 0x07,
            0x00, 0x00, 0x00, 0xc3,
        ];
        let text = c(&code);
        assert!(
            text.contains("  *(struct { int at_0; int at_4; long at_8; } *)a = { b, 2, 7 };"),
            "{text}"
        );
        let kept = c_with(&code, &names, &[("struct-initializers", "keep")]);
        assert!(
            kept.contains("  *(int *)a = b;\n  *(int *)(a + 4) = 2;\n  *(long *)(a + 8) = 7;"),
            "{kept}"
        );
        // Two stores to one field are two stores.
        // mov dword [rdi], 1; mov dword [rdi], 2; ret
        let twice = c(&[
            0xc7, 0x07, 0x01, 0x00, 0x00, 0x00, 0xc7, 0x07, 0x02, 0x00, 0x00, 0x00, 0xc3,
        ]);
        assert!(!twice.contains("struct {"), "{twice}");
    }

    /// Symbols that know `die` at 0x2000 never returns, and `checked` at
    /// 0x3000 does not when its first parameter is zero.
    struct Dying;

    impl Symbols for Dying {
        fn function_name(&self, address: u64) -> Option<String> {
            match address {
                0x2000 => Some("die".to_string()),
                0x3000 => Some("checked".to_string()),
                _ => None,
            }
        }

        fn returns(&self, address: u64) -> bool {
            address != 0x2000
        }

        fn noreturn_when(&self, address: u64) -> Vec<(Vec<String>, AstNode)> {
            if address == 0x3000 {
                vec![(
                    vec!["p".to_string(), "v".to_string()],
                    AstNode::binary(AstNode::var("p"), BinaryOp::Equal, AstNode::constant(0, 8)),
                )]
            } else {
                Vec::new()
            }
        }
    }

    #[test]
    fn a_call_that_never_returns_ends_its_path_and_the_condition_is_noted() {
        // test edi, edi; js .die; lea eax, [rdi+rdi]; ret; .die: mov edi, 3;
        // call die — and nothing after: the walk gives the block no
        // successor, since die never returns.
        let code = [
            0x85, 0xff, 0x78, 0x04, 0x8d, 0x04, 0x3f, 0xc3, 0xbf, 0x03, 0x00, 0x00, 0x00, 0xe8,
            0xee, 0x0f, 0x00, 0x00,
        ];
        let disasm = decode(&code);
        struct Ends;
        impl Entries for Ends {
            fn is_function(&self, _address: u64) -> bool {
                false
            }
            fn is_import_slot(&self, _slot: u64) -> bool {
                false
            }
            fn returns(&self, callee: u64) -> bool {
                callee != 0x2000
            }
        }
        let cfg = crate::cfgwalk::resolve_branches_among(
            &Disasm {
                instructions: disasm.clone(),
                ..Default::default()
            },
            BASE,
            &Ends,
        );
        let options = Options::default();
        let function = lift_block(&disasm, BASE, "f", Abi::SystemV, &Dying, &options)
            .unwrap_or_else(|error| panic!("{error}: {cfg:?}"));
        let text = emit_function(&function, &options).text();
        // The arm that dies is the guard: nothing is printed for the end of
        // its path, and the rest follows unnested.
        assert!(
            text.contains("  if (a < 0) {\n    die(3);\n  }\n  return a + a;"),
            "{text}"
        );
        assert!(!text.contains("__builtin_unreachable"), "{text}");
        // The transpiler writes the marker for the compiler.
        let cpp = crate::emit::emit_node_c(&AstNode::Intrinsic {
            name: UNREACHABLE.to_string(),
            args: Vec::new(),
        });
        assert_eq!(cpp.trim_end(), "__builtin_unreachable();");
        // The function's own note, after the return's reason.
        assert!(
            text.contains("\n// does not return when a < 0\nint f(int a)"),
            "{text}"
        );
        assert_eq!(
            function.noreturn_when,
            vec![AstNode::binary(
                AstNode::var("a"),
                BinaryOp::Less,
                AstNode::constant(0, 4)
            )]
        );
    }

    #[test]
    fn a_call_to_a_helper_that_may_not_return_is_noted_with_the_arguments() {
        // mov rdi, rsi; mov esi, 5; call checked; ret: checked does not
        // return when its first parameter is zero, which here is this
        // function's own `b`.
        let code = [
            0x48, 0x89, 0xf7, 0xbe, 0x05, 0x00, 0x00, 0x00, 0xe8, 0xf3, 0x1f, 0x00, 0x00, 0xc3,
        ];
        let text = c_with(&code, &Dying, &[]);
        assert!(
            text.contains("  checked(b, 5);  // checked does not return when b == 0"),
            "{text}"
        );
        // Without an argument for the parameter the condition names, nothing
        // is said: mov esi, 5; call checked; ret
        let text = c_with(
            &[
                0xbe, 0x05, 0x00, 0x00, 0x00, 0xe8, 0xf6, 0x1f, 0x00, 0x00, 0xc3,
            ],
            &Dying,
            &[],
        );
        assert!(!text.contains("does not return when"), "{text}");
        // A function whose every path ends in such a call does not return.
        // mov edi, 1; call die
        let text = c_with(
            &[0xbf, 0x01, 0x00, 0x00, 0x00, 0xe8, 0xf6, 0x0f, 0x00, 0x00],
            &Dying,
            &[],
        );
        assert!(
            text.contains("// does not return\nvoid f(void)\n{\n  die(1);\n}"),
            "{text}"
        );
    }

    #[test]
    fn the_arguments_stand_in_for_the_parameters_all_at_once() {
        // checked's parameters are named as this function's own, a and b,
        // and are passed swapped: mov rax, rdi; mov rdi, rsi; mov rsi, rax;
        // call checked; ret. Its `a == 0` is on this function's b — and is
        // not then substituted on into a.
        struct Swapped;
        impl Symbols for Swapped {
            fn function_name(&self, address: u64) -> Option<String> {
                (address == 0x3000).then(|| "checked".to_string())
            }

            fn noreturn_when(&self, address: u64) -> Vec<(Vec<String>, AstNode)> {
                if address == 0x3000 {
                    vec![(
                        vec!["a".to_string(), "b".to_string()],
                        AstNode::binary(AstNode::var("a"), BinaryOp::Equal, AstNode::constant(0, 8)),
                    )]
                } else {
                    Vec::new()
                }
            }
        }
        let code = [
            0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xc6, 0xe8, 0xf2, 0x1f, 0x00, 0x00,
            0xc3,
        ];
        let text = c_with(&code, &Swapped, &[]);
        assert!(
            text.contains("checked(b, a);  // checked does not return when b == 0"),
            "{text}"
        );
    }

    #[test]
    fn the_code_after_a_call_that_never_returns_is_not_the_functions() {
        // mov edi, 1; call die; ret: the walk among the lift's own symbols
        // ends the block at the call, and the ret after it is never lifted.
        let code = [
            0xbf, 0x01, 0x00, 0x00, 0x00, 0xe8, 0xf6, 0x0f, 0x00, 0x00, 0xc3,
        ];
        let text = c_with(&code, &Dying, &[]);
        assert!(
            text.contains("// does not return\nvoid f(void)\n{\n  die(1);\n}"),
            "{text}"
        );
        assert!(!text.contains("  return"), "{text}");
    }

    #[test]
    fn code_that_falls_into_the_next_function_tail_calls_it() {
        // mov edi, 1 — and inner, the next function, starts right after:
        // the fall into it is a tail call to it.
        struct Inner;
        impl Symbols for Inner {
            fn function_name(&self, address: u64) -> Option<String> {
                (address == BASE + 5).then(|| "inner".to_string())
            }
        }
        let text = c_with(&[0xbf, 0x01, 0x00, 0x00, 0x00], &Inner, &[]);
        assert!(text.contains("inner(1)"), "{text}");
        assert!(!text.contains("not lifted"), "{text}");
    }

    #[test]
    fn conditions_are_over_the_parameters_and_hold_at_entry() {
        let dies = |code: u64| {
            vec![
                Statement::plain(
                    AstNode::Call {
                        callee: Box::new(AstNode::FunctionName {
                            name: "die".to_string(),
                            address: 0x2000,
                        }),
                        args: vec![AstNode::constant(code, 4)],
                    },
                    Vec::new(),
                ),
                Statement::plain(
                    AstNode::Intrinsic {
                        name: UNREACHABLE.to_string(),
                        args: Vec::new(),
                    },
                    Vec::new(),
                ),
            ]
        };
        let guard = |condition: AstNode, code: u64| Statement {
            node: condition,
            addresses: Vec::new(),
            kind: StatementKind::If {
                then_part: dies(code),
                else_part: Vec::new(),
            },
        };
        let is_zero = |name: &str| {
            AstNode::binary(AstNode::var(name), BinaryOp::Equal, AstNode::constant(0, 8))
        };
        let store = |name: &str| {
            Statement::plain(
                AstNode::Assign {
                    lhs: Box::new(AstNode::var(name)),
                    rhs: Box::new(AstNode::constant(1, 8)),
                },
                Vec::new(),
            )
        };
        let locals = vec!["v1".to_string()];
        // A condition on a local is not said; one on a global is.
        let body = vec![
            guard(is_zero("a"), 1),
            guard(is_zero("v1"), 2),
            guard(is_zero("status"), 3),
        ];
        assert_eq!(
            noreturn_conditions(&body, &locals),
            vec![is_zero("a"), is_zero("status")]
        );
        // Past a return, nothing more is said.
        let returns = Statement {
            node: AstNode::var("a"),
            addresses: Vec::new(),
            kind: StatementKind::If {
                then_part: vec![Statement::plain(
                    AstNode::Return { value: None },
                    Vec::new(),
                )],
                else_part: Vec::new(),
            },
        };
        let body = vec![guard(is_zero("a"), 1), returns, guard(is_zero("b"), 2)];
        assert_eq!(noreturn_conditions(&body, &locals), vec![is_zero("a")]);
        // Nor past a store to a parameter — while a store to a local
        // changes nothing a caller sees.
        let body = vec![store("a"), guard(is_zero("a"), 1)];
        assert!(noreturn_conditions(&body, &locals).is_empty());
        let body = vec![store("v1"), guard(is_zero("a"), 1)];
        assert_eq!(noreturn_conditions(&body, &locals), vec![is_zero("a")]);
    }

    /// The analyst's words on the walk, by site.
    struct Guided {
        taken: &'static [(u64, bool)],
        next: &'static [(u64, bool)],
    }

    impl crate::cfgwalk::Entries for Guided {
        fn is_function(&self, _address: u64) -> bool {
            false
        }

        fn is_import_slot(&self, _slot: u64) -> bool {
            false
        }

        fn follows_taken(&self, site: u64) -> Option<bool> {
            self.taken
                .iter()
                .find(|(at, _)| *at == site)
                .map(|(_, on)| *on)
        }

        fn follows_next(&self, site: u64) -> Option<bool> {
            self.next
                .iter()
                .find(|(at, _)| *at == site)
                .map(|(_, on)| *on)
        }
    }

    /// The stages of `bytes` walked under the analyst's `words`.
    fn guided_stages(bytes: &[u8], words: &Guided) -> Stages {
        let disasm = Disasm {
            file_offset_of_segment: 0,
            instructions: decode(bytes),
        };
        let cfg = crate::cfgwalk::resolve_branches_among(&disasm, BASE, words);
        lift_stages(
            &disasm,
            &cfg,
            BASE,
            "f",
            Bitness::Bits64,
            Abi::SystemV,
            &names,
            &Options::default(),
        )
        .expect("the code lifts")
    }

    /// No memory, no calls followed.
    struct Nowhere;

    impl crate::emulate::World for Nowhere {
        fn read(&self, _address: u64, _len: usize) -> Option<Vec<u8>> {
            None
        }

        fn address_of(&self, _name: &str) -> Option<u64> {
            None
        }
    }

    // 0x1000: test edi, edi ; 85 ff
    // 0x1002: je 0x1005     ; 74 01
    // 0x1004: ret           ; c3
    // 0x1005: (bad)         ; 06 — no instruction in 64-bit code
    const INTO_JUNK: &[u8] = &[0x85, 0xff, 0x74, 0x01, 0xc3, 0x06];

    #[test]
    fn a_branch_into_bytes_that_do_not_decode_is_not_analyzed_and_says_so() {
        let stages = guided_stages(
            INTO_JUNK,
            &Guided {
                taken: &[],
                next: &[],
            },
        );
        let text = without_reason(&emit_function(&stages.function, &Options::default()));
        assert_eq!(
            text,
            "// analysis halted at 0x1005: the target does not decode\n\
             void f(int a)\n{\n  if (a == 0) {\n    // not analyzed: 0x1005\n  }\n  return;\n}"
        );
        // A path that goes there stops there; one that does not returns.
        let run = crate::emulate::run(&stages, &[0], &Nowhere, &Default::default());
        assert_eq!(
            run.stop,
            crate::emulate::Stop::Halted {
                at: Some(0x1002),
                target: 0x1005
            }
        );
        assert_eq!(run.stop.text(), "stopped at 0x1002: 0x1005 is not analyzed");
        let run = crate::emulate::run(&stages, &[1], &Nowhere, &Default::default());
        assert_eq!(run.stop, crate::emulate::Stop::Returned(None));
        // The C++ traps there, and compiles.
        let program = crate::transpile::program(&crate::transpile::Program {
            functions: vec![&stages],
            ..Default::default()
        });
        assert!(program.contains("__builtin_trap();"), "{program}");
        assert!(!program.contains("__analysis_halted"), "{program}");
    }

    #[test]
    fn a_side_the_analyst_says_not_to_follow_is_not_analyzed() {
        // `taken off` at the je leaves the ret at 0x1005 out.
        // 0x1000 test edi, edi; 0x1002 je 0x1005; 0x1004 ret; 0x1005 ret
        let bytes = [0x85, 0xff, 0x74, 0x01, 0xc3, 0xc3];
        let stages = guided_stages(
            &bytes,
            &Guided {
                taken: &[(0x1002, false)],
                next: &[],
            },
        );
        let text = without_reason(&emit_function(&stages.function, &Options::default()));
        assert!(
            text.contains("  if (a == 0) {\n    // not analyzed: 0x1005\n  }\n  return;"),
            "{text}"
        );
        assert!(
            text.contains("// analysis halted at 0x1005: told to"),
            "{text}"
        );
        // `next off` halts the fall-through instead: the guard turns round.
        let stages = guided_stages(
            &bytes,
            &Guided {
                taken: &[],
                next: &[(0x1002, false)],
            },
        );
        let text = without_reason(&emit_function(&stages.function, &Options::default()));
        assert!(text.contains("// not analyzed: 0x1004"), "{text}");
        assert!(
            text.contains("// analysis halted at 0x1004: told to"),
            "{text}"
        );
        // A halted path is no proof the function never returns.
        assert!(!text.contains("does not return"), "{text}");
        // `taken on` follows a target that does not decode, and the lift
        // refuses the bytes it finds there as it always did.
        let disasm = Disasm {
            file_offset_of_segment: 0,
            instructions: decode(INTO_JUNK),
        };
        let cfg = crate::cfgwalk::resolve_branches_among(
            &disasm,
            BASE,
            &Guided {
                taken: &[(0x1002, true)],
                next: &[],
            },
        );
        assert!(cfg.halts.is_empty(), "{:?}", cfg.halts);
        assert!(lift_function(
            &disasm,
            &cfg,
            BASE,
            "f",
            Bitness::Bits64,
            Abi::SystemV,
            &names,
            &Options::default(),
        )
        .is_err());
    }

    #[test]
    fn a_jump_the_walk_does_not_follow_ends_its_path() {
        // 0x1000 test edi, edi; 0x1002 je 0x1007; 0x1004 jmp 0x1008;
        // 0x1006 ret; 0x1007 ret; 0x1008 (bad)
        let bytes = [0x85, 0xff, 0x74, 0x03, 0xeb, 0x02, 0xc3, 0xc3, 0x06];
        let stages = guided_stages(
            &bytes,
            &Guided {
                taken: &[],
                next: &[],
            },
        );
        let text = without_reason(&emit_function(&stages.function, &Options::default()));
        assert!(text.contains("// not analyzed: 0x1008"), "{text}");
        assert!(text.contains("return;"), "{text}");
    }
}
