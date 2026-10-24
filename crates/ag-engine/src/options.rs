//! The option registry: every judgment call the engine makes, named.
//!
//! Reversers and pwners want different output from the same engine. Where
//! the lifter, the structurer or the emitter could reasonably go either way
//! — fold a counted loop into a `for` or leave it a `while`, name a merged
//! register after itself or by number, print a load from named data as the
//! name or as a cast — the choice is a row of [`OPTIONS`] and a field of
//! [`Options`], set per run with `--option NAME VALUE`.
//!
//! Each row carries its *symptoms*: what the output looks like when you
//! want to flip it. [`catalog_markdown`] opens with the symptom index built
//! from them — *if the output shows X, try Y* — which is the part an agent
//! reads; [`catalog_json`] is the same table for a program. `ag catalog
//! --check` and a test hold the committed `docs/options.md` to the
//! generated one, so the table and the document cannot drift apart.
//!
//! A row is declarative: its name, the phase that reads it, its tier, its
//! type, its default, one line of description and its symptoms. The
//! [`Options`] value holds one typed field per row; [`Options::set`] and
//! [`Options::get`] map names to fields, and a test holds the two in step:
//! every row's default is the field's default, every choice sets, and
//! nothing else does.

use std::fmt;

use crate::lift::Abi;

/// The phase of the engine that reads an option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Bytes to instructions.
    Decode,
    /// Instructions to statements and conditions.
    Lift,
    /// Statements and the graph to `if`, `while`, `for` and `goto`.
    Structure,
    /// The tree to text.
    Emit,
}

impl Phase {
    /// Every phase, in pipeline order.
    pub const ALL: [Phase; 4] = [Phase::Decode, Phase::Lift, Phase::Structure, Phase::Emit];

    /// The phase's name, as the catalog prints it.
    pub fn name(self) -> &'static str {
        match self {
            Phase::Decode => "decode",
            Phase::Lift => "lift",
            Phase::Structure => "structure",
            Phase::Emit => "emit",
        }
    }
}

/// What kind of decision an option is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Changes the shape of the output: what statements there are.
    Transform,
    /// Changes what the engine concludes about the code.
    Analysis,
    /// Changes how the same conclusion is spelled.
    Rendering,
}

impl Tier {
    /// The tier's name, as the catalog prints it.
    pub fn name(self) -> &'static str {
        match self {
            Tier::Transform => "transform",
            Tier::Analysis => "analysis",
            Tier::Rendering => "rendering",
        }
    }
}

/// The type of an option's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// One of a fixed set of words.
    Choice(&'static [&'static str]),
    /// An integer in a range, both ends included.
    Integer { min: i64, max: i64 },
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Kind::Choice(choices) => f.write_str(&choices.join(" | ")),
            Kind::Integer { min, max } => write!(f, "integer {min}..{max}"),
        }
    }
}

/// One symptom: what the output shows, and the value to try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symptom {
    /// What the output shows, completing "if the output shows …".
    pub shows: &'static str,
    /// The value of the option to try.
    pub value: &'static str,
}

/// One row of the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionSpec {
    /// The name, in kebab-case, as `--option` takes it.
    pub name: &'static str,
    /// The phase that reads it.
    pub phase: Phase,
    /// The kind of decision it is.
    pub tier: Tier,
    /// The type of its value.
    pub kind: Kind,
    /// The default value, spelled as `--option` would take it.
    pub default: &'static str,
    /// One line: what the option decides.
    pub description: &'static str,
    /// What the output looks like when you want to flip it.
    pub symptoms: &'static [Symptom],
}

/// A symptom row.
const fn symptom(shows: &'static str, value: &'static str) -> Symptom {
    Symptom { shows, value }
}

/// The registry: every option, by phase and then by name.
pub const OPTIONS: &[OptionSpec] = &[
    OptionSpec {
        name: "abi",
        phase: Phase::Lift,
        tier: Tier::Analysis,
        kind: Kind::Choice(&["auto", "sysv", "win64"]),
        default: "auto",
        description: "The integer calling convention: read from the image's language, or System V (`rdi, rsi, rdx, rcx, r8, r9`) or Microsoft x64 (`rcx, rdx, r8, r9`) whatever the image says.",
        symptoms: &[
            symptom(
                "`not lifted yet: rcx is read before it is written` on an ELF built for the Microsoft convention",
                "win64",
            ),
            symptom(
                "`not lifted yet: rdi is read before it is written` on a PE built with a System V compiler",
                "sysv",
            ),
        ],
    },
    OptionSpec {
        name: "parameters",
        phase: Phase::Lift,
        tier: Tier::Analysis,
        kind: Kind::Choice(&["last-read", "convention"]),
        default: "last-read",
        description: "Which argument registers are parameters: the ones through the last one read, a gap declared `long`, or every register of the convention.",
        symptoms: &[
            symptom(
                "a function you know takes more arguments than its signature shows, because the tail of them is only passed on",
                "convention",
            ),
            symptom(
                "`long a` in a signature where nothing reads `a`",
                "last-read",
            ),
        ],
    },
    OptionSpec {
        name: "merged-register-names",
        phase: Phase::Lift,
        tier: Tier::Rendering,
        kind: Kind::Choice(&["register", "numbered"]),
        default: "register",
        description: "How a register that differs where two paths join is named once it is a variable: after the register (`eax`, `eax_2`), or by number (`var_1`, `var_2`).",
        symptoms: &[
            symptom(
                "`eax`, `eax_2` and `edi` declared as locals, reading like a listing and not like C",
                "numbered",
            ),
            symptom(
                "`var_1` and `var_2` where you want to see which register the compiler used",
                "register",
            ),
        ],
    },
    OptionSpec {
        name: "stack-slot-names",
        phase: Phase::Lift,
        tier: Tier::Rendering,
        kind: Kind::Choice(&["hex", "decimal"]),
        default: "hex",
        description: "How a stack slot is named, by its offset from the entry stack pointer: `local_14` in hex, or `local_20` in decimal.",
        symptoms: &[
            symptom(
                "`local_14` next to a listing whose offsets are decimal",
                "decimal",
            ),
            symptom(
                "`local_20` next to a listing that says `[rbp-0x14]`",
                "hex",
            ),
        ],
    },
    OptionSpec {
        name: "pointer-loads",
        phase: Phase::Lift,
        tier: Tier::Rendering,
        kind: Kind::Choice(&["named", "cast"]),
        default: "named",
        description: "A load or store at an address the image names as data: the data's name (`counter`), or the typed cast every other address gets (`*(int *)0x4010`).",
        symptoms: &[
            symptom(
                "`counter` where you want the address the instruction named, to check it against the bytes",
                "cast",
            ),
            symptom(
                "`*(int *)0x4010` where the image has a name for the data",
                "named",
            ),
        ],
    },
    OptionSpec {
        name: "operand-order",
        phase: Phase::Lift,
        tier: Tier::Rendering,
        kind: Kind::Choice(&["instruction", "canonical"]),
        default: "instruction",
        description: "The operands of `+`, `*`, `&`, `|` and `^`: in the order the instruction names them (`b + a`), or canonical, variables alphabetical and constants last (`a + b`).",
        symptoms: &[
            symptom(
                "`b + a` and `a + b` in two functions that do the same thing",
                "canonical",
            ),
            symptom(
                "`a + b` where the listing says `add esi, edi` and you want the C to follow it",
                "instruction",
            ),
        ],
    },
    OptionSpec {
        name: "unsigned-compare",
        phase: Phase::Lift,
        tier: Tier::Rendering,
        kind: Kind::Choice(&["cast", "bare"]),
        default: "cast",
        description: "A comparison whose condition code is unsigned (`jb`, `ja`, `jbe`, `jae`): both sides cast, `(unsigned int)a < (unsigned int)b`, or written bare, `a < b`.",
        symptoms: &[
            symptom(
                "`(unsigned int)a < (unsigned int)b` cluttering every bounds check",
                "bare",
            ),
            symptom(
                "`a < b` where you need to know whether a negative `a` passes",
                "cast",
            ),
        ],
    },
    OptionSpec {
        name: "dead-compares",
        phase: Phase::Lift,
        tier: Tier::Transform,
        kind: Kind::Choice(&["drop", "keep"]),
        default: "drop",
        description: "A `cmp` or `test` whose flags no branch reads: dropped, or kept as the statement `__cmp(a, b);` or `__test(a, b);`.",
        symptoms: &[
            symptom(
                "a `cmp` in the listing that the C says nothing about",
                "keep",
            ),
            symptom(
                "`__cmp(a, b);` statements that do nothing",
                "drop",
            ),
        ],
    },
    OptionSpec {
        name: "tail-calls",
        phase: Phase::Lift,
        tier: Tier::Transform,
        kind: Kind::Choice(&["return", "refuse"]),
        default: "return",
        description: "A `jmp` to another function with the stack as it was at entry: lifted as the call and the return it stands for, `return callee(args);` — a function that is only the jump is a thunk, printed as `// thunk for callee` — or refused, naming the callee.",
        symptoms: &[
            symptom(
                "`return printf(a);` where the listing ends in `jmp`, and you want the functions that jump rather than call to stand out as refusals",
                "refuse",
            ),
            symptom(
                "`not lifted yet: a tail call to printf at 0x…` on a function that ends in `jmp printf`",
                "return",
            ),
        ],
    },
    OptionSpec {
        name: "return-liveness",
        phase: Phase::Lift,
        tier: Tier::Analysis,
        kind: Kind::Choice(&["callers", "presence"]),
        default: "callers",
        description: "Whether a function returns a value, and at what width: from use — a caller that reads `eax`/`rax` after the call decides it, and with no caller in the image only a value the function wrote itself counts, not a callee's leftover — or from presence, `rax` written on the way to a `ret`, whatever reads it.",
        symptoms: &[
            symptom(
                "`void f(…)` with `// void: no caller reads the result` on a function you know returns a value, whose callers in the image all discard it",
                "presence",
            ),
            symptom(
                "`long f(void)` and `return g();` on a function whose source is `void`, the value only what the callee left in `rax`",
                "callers",
            ),
            symptom(
                "`not lifted yet: returns a value at one ret and nothing at another` on glue such as `__do_global_dtors_aux`",
                "callers",
            ),
        ],
    },
    OptionSpec {
        name: "loop-form",
        phase: Phase::Structure,
        tier: Tier::Transform,
        kind: Kind::Choice(&["for", "while"]),
        default: "for",
        description: "A counted loop, `init; while (cond) { …; step }`: folded into `for (init; cond; step)`, or left as the `while` with its init before and its step last.",
        symptoms: &[
            symptom(
                "a `for` whose step is not the increment you expected, or whose init is a statement that belongs before the loop",
                "while",
            ),
            symptom(
                "`i = 0; while (i < n) { …; i = i + 1; }` where a `for` would read better",
                "for",
            ),
        ],
    },
    OptionSpec {
        name: "shared-tail",
        phase: Phase::Structure,
        tier: Tier::Transform,
        kind: Kind::Choice(&["goto", "duplicate"]),
        default: "goto",
        description: "A run of statements two paths share that neither branch dominates: reached by `goto` to a label on it, or copied into the second path when it runs straight to a `return`.",
        symptoms: &[
            symptom(
                "`goto label_…;` to a `return` a few lines up",
                "duplicate",
            ),
            symptom(
                "the same `return` statements repeated in two arms",
                "goto",
            ),
        ],
    },
    OptionSpec {
        name: "constant-style",
        phase: Phase::Emit,
        tier: Tier::Rendering,
        kind: Kind::Choice(&["mixed", "decimal", "hex"]),
        default: "mixed",
        description: "How a constant is spelled: decimal below 10 and hex from 10 up, all decimal, or all hex.",
        symptoms: &[
            symptom("`0x64` where the source said `100`", "decimal"),
            symptom("`8` where the source said `0x8`, a mask or an offset", "hex"),
            symptom("`16777216` where `0x1000000` would be read at a glance", "mixed"),
        ],
    },
    OptionSpec {
        name: "indent",
        phase: Phase::Emit,
        tier: Tier::Rendering,
        kind: Kind::Integer { min: 1, max: 8 },
        default: "2",
        description: "The spaces one level of a body is indented by.",
        symptoms: &[symptom(
            "bodies indented two spaces next to source indented four",
            "4",
        )],
    },
];

/// The row named `name`, when there is one.
pub fn spec(name: &str) -> Option<&'static OptionSpec> {
    OPTIONS.iter().find(|spec| spec.name == name)
}

/// What went wrong with an option: an unknown name, or a value the row
/// does not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionError {
    /// No row has the name.
    Unknown { name: String },
    /// The row does not take the value.
    BadValue {
        name: String,
        value: String,
        takes: String,
    },
    /// A `--option` was given a name and no value.
    MissingValue { name: String },
}

impl fmt::Display for OptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionError::Unknown { name } => {
                let names: Vec<&str> = OPTIONS.iter().map(|spec| spec.name).collect();
                write!(
                    f,
                    "no option named {name:?}; the options are {}",
                    names.join(", ")
                )
            }
            OptionError::BadValue { name, value, takes } => {
                write!(f, "option {name:?} takes {takes}, not {value:?}")
            }
            OptionError::MissingValue { name } => {
                write!(f, "option {name:?} was given no value")
            }
        }
    }
}

impl std::error::Error for OptionError {}

/// Which convention the lifter uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AbiChoice {
    /// The one the image's language implies.
    #[default]
    Auto,
    /// System V AMD64, whatever the image says.
    SysV,
    /// Microsoft x64, whatever the image says.
    Win64,
}

/// Which argument registers are parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Parameters {
    /// Through the last one read; a gap is declared `long`.
    #[default]
    LastRead,
    /// Every argument register of the convention.
    Convention,
}

/// How a register that became a variable at a join is named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MergedNames {
    /// After the register: `eax`, then `eax_2`.
    #[default]
    Register,
    /// By number: `var_1`, `var_2`.
    Numbered,
}

/// How a stack slot is named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlotNames {
    /// `local_14`, the offset in hex.
    #[default]
    Hex,
    /// `local_20`, the offset in decimal.
    Decimal,
}

/// How a load at an address the image names is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PointerLoads {
    /// The data's name.
    #[default]
    Named,
    /// `*(int *)0x4010`, like any other address.
    Cast,
}

/// The order of the operands of a commutative operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OperandOrder {
    /// As the instruction names them.
    #[default]
    Instruction,
    /// Variables alphabetical, constants last.
    Canonical,
}

/// How an unsigned comparison is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnsignedCompare {
    /// Both sides cast to the unsigned type.
    #[default]
    Cast,
    /// Bare, as the signed one is.
    Bare,
}

/// What becomes of a `cmp` or `test` no branch reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeadCompares {
    /// Nothing.
    #[default]
    Drop,
    /// A `__cmp(a, b);` or `__test(a, b);` statement.
    Keep,
}

/// What becomes of a `jmp` to another function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TailCalls {
    /// The call and the return it stands for: `return callee(args);`.
    #[default]
    Return,
    /// Refused, naming the callee.
    Refuse,
}

/// How the lifter decides whether a function returns a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReturnLiveness {
    /// From use: a caller that reads the result, or, with no caller in the
    /// image, a value the function wrote itself.
    #[default]
    Callers,
    /// From presence: `rax` written on the way to a `ret`.
    Presence,
}

/// The form of a counted loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoopForm {
    /// `for (init; cond; step)`.
    #[default]
    For,
    /// `init; while (cond) { …; step }`.
    While,
}

/// How a tail two paths share is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SharedTail {
    /// `goto` to a label on it.
    #[default]
    Goto,
    /// Copied, when it runs straight to a `return`.
    Duplicate,
}

/// How a constant is spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConstantStyle {
    /// Decimal below 10, hex from 10 up.
    #[default]
    Mixed,
    /// Always decimal.
    Decimal,
    /// Always hex.
    Hex,
}

/// The options of one run: one typed field per row of [`OPTIONS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub abi: AbiChoice,
    pub parameters: Parameters,
    pub merged_register_names: MergedNames,
    pub stack_slot_names: SlotNames,
    pub pointer_loads: PointerLoads,
    pub operand_order: OperandOrder,
    pub unsigned_compare: UnsignedCompare,
    pub dead_compares: DeadCompares,
    pub tail_calls: TailCalls,
    pub return_liveness: ReturnLiveness,
    pub loop_form: LoopForm,
    pub shared_tail: SharedTail,
    pub constant_style: ConstantStyle,
    pub indent: u8,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            abi: AbiChoice::default(),
            parameters: Parameters::default(),
            merged_register_names: MergedNames::default(),
            stack_slot_names: SlotNames::default(),
            pointer_loads: PointerLoads::default(),
            operand_order: OperandOrder::default(),
            unsigned_compare: UnsignedCompare::default(),
            dead_compares: DeadCompares::default(),
            tail_calls: TailCalls::default(),
            return_liveness: ReturnLiveness::default(),
            loop_form: LoopForm::default(),
            shared_tail: SharedTail::default(),
            constant_style: ConstantStyle::default(),
            indent: 2,
        }
    }
}

/// Pick the variant `value` names out of `choices`, for the row `spec`.
fn choose<T: Copy>(
    spec: &OptionSpec,
    value: &str,
    choices: &[(&str, T)],
) -> Result<T, OptionError> {
    choices
        .iter()
        .find(|(name, _)| *name == value)
        .map(|(_, variant)| *variant)
        .ok_or_else(|| OptionError::BadValue {
            name: spec.name.to_string(),
            value: value.to_string(),
            takes: spec.kind.to_string(),
        })
}

impl Options {
    /// The options with every `(name, value)` pair applied, in order.
    pub fn from_pairs<'p>(
        pairs: impl IntoIterator<Item = (&'p str, &'p str)>,
    ) -> Result<Options, OptionError> {
        let mut options = Options::default();
        for (name, value) in pairs {
            options.set(name, value)?;
        }
        Ok(options)
    }

    /// The options from the flat list `--option NAME VALUE` leaves: names and
    /// values alternating.
    pub fn from_flat<S: AsRef<str>>(flat: &[S]) -> Result<Options, OptionError> {
        let mut options = Options::default();
        for pair in flat.chunks(2) {
            match pair {
                [name, value] => options.set(name.as_ref(), value.as_ref())?,
                [name] => {
                    return Err(OptionError::MissingValue {
                        name: name.as_ref().to_string(),
                    })
                }
                _ => unreachable!("chunks of two"),
            }
        }
        Ok(options)
    }

    /// Set the option `name` to `value`.
    ///
    /// An unknown name or a value the row does not take is an error that
    /// names the row and what it takes.
    pub fn set(&mut self, name: &str, value: &str) -> Result<(), OptionError> {
        let spec = spec(name).ok_or_else(|| OptionError::Unknown {
            name: name.to_string(),
        })?;
        match name {
            "abi" => {
                self.abi = choose(
                    spec,
                    value,
                    &[
                        ("auto", AbiChoice::Auto),
                        ("sysv", AbiChoice::SysV),
                        ("win64", AbiChoice::Win64),
                    ],
                )?
            }
            "parameters" => {
                self.parameters = choose(
                    spec,
                    value,
                    &[
                        ("last-read", Parameters::LastRead),
                        ("convention", Parameters::Convention),
                    ],
                )?
            }
            "merged-register-names" => {
                self.merged_register_names = choose(
                    spec,
                    value,
                    &[
                        ("register", MergedNames::Register),
                        ("numbered", MergedNames::Numbered),
                    ],
                )?
            }
            "stack-slot-names" => {
                self.stack_slot_names = choose(
                    spec,
                    value,
                    &[("hex", SlotNames::Hex), ("decimal", SlotNames::Decimal)],
                )?
            }
            "pointer-loads" => {
                self.pointer_loads = choose(
                    spec,
                    value,
                    &[("named", PointerLoads::Named), ("cast", PointerLoads::Cast)],
                )?
            }
            "operand-order" => {
                self.operand_order = choose(
                    spec,
                    value,
                    &[
                        ("instruction", OperandOrder::Instruction),
                        ("canonical", OperandOrder::Canonical),
                    ],
                )?
            }
            "unsigned-compare" => {
                self.unsigned_compare = choose(
                    spec,
                    value,
                    &[
                        ("cast", UnsignedCompare::Cast),
                        ("bare", UnsignedCompare::Bare),
                    ],
                )?
            }
            "dead-compares" => {
                self.dead_compares = choose(
                    spec,
                    value,
                    &[("drop", DeadCompares::Drop), ("keep", DeadCompares::Keep)],
                )?
            }
            "tail-calls" => {
                self.tail_calls = choose(
                    spec,
                    value,
                    &[("return", TailCalls::Return), ("refuse", TailCalls::Refuse)],
                )?
            }
            "return-liveness" => {
                self.return_liveness = choose(
                    spec,
                    value,
                    &[
                        ("callers", ReturnLiveness::Callers),
                        ("presence", ReturnLiveness::Presence),
                    ],
                )?
            }
            "loop-form" => {
                self.loop_form = choose(
                    spec,
                    value,
                    &[("for", LoopForm::For), ("while", LoopForm::While)],
                )?
            }
            "shared-tail" => {
                self.shared_tail = choose(
                    spec,
                    value,
                    &[
                        ("goto", SharedTail::Goto),
                        ("duplicate", SharedTail::Duplicate),
                    ],
                )?
            }
            "constant-style" => {
                self.constant_style = choose(
                    spec,
                    value,
                    &[
                        ("mixed", ConstantStyle::Mixed),
                        ("decimal", ConstantStyle::Decimal),
                        ("hex", ConstantStyle::Hex),
                    ],
                )?
            }
            "indent" => {
                let Kind::Integer { min, max } = spec.kind else {
                    unreachable!("indent is an integer");
                };
                let bad = || OptionError::BadValue {
                    name: spec.name.to_string(),
                    value: value.to_string(),
                    takes: spec.kind.to_string(),
                };
                let n: i64 = value.trim().parse().map_err(|_| bad())?;
                if n < min || n > max {
                    return Err(bad());
                }
                self.indent = n as u8;
            }
            _ => unreachable!("every row of OPTIONS is matched above: {name}"),
        }
        Ok(())
    }

    /// The value of the option `name`, spelled as `--option` takes it;
    /// `None` for a name no row has.
    pub fn get(&self, name: &str) -> Option<String> {
        Some(
            match name {
                "abi" => match self.abi {
                    AbiChoice::Auto => "auto",
                    AbiChoice::SysV => "sysv",
                    AbiChoice::Win64 => "win64",
                },
                "parameters" => match self.parameters {
                    Parameters::LastRead => "last-read",
                    Parameters::Convention => "convention",
                },
                "merged-register-names" => match self.merged_register_names {
                    MergedNames::Register => "register",
                    MergedNames::Numbered => "numbered",
                },
                "stack-slot-names" => match self.stack_slot_names {
                    SlotNames::Hex => "hex",
                    SlotNames::Decimal => "decimal",
                },
                "pointer-loads" => match self.pointer_loads {
                    PointerLoads::Named => "named",
                    PointerLoads::Cast => "cast",
                },
                "operand-order" => match self.operand_order {
                    OperandOrder::Instruction => "instruction",
                    OperandOrder::Canonical => "canonical",
                },
                "unsigned-compare" => match self.unsigned_compare {
                    UnsignedCompare::Cast => "cast",
                    UnsignedCompare::Bare => "bare",
                },
                "dead-compares" => match self.dead_compares {
                    DeadCompares::Drop => "drop",
                    DeadCompares::Keep => "keep",
                },
                "tail-calls" => match self.tail_calls {
                    TailCalls::Return => "return",
                    TailCalls::Refuse => "refuse",
                },
                "return-liveness" => match self.return_liveness {
                    ReturnLiveness::Callers => "callers",
                    ReturnLiveness::Presence => "presence",
                },
                "loop-form" => match self.loop_form {
                    LoopForm::For => "for",
                    LoopForm::While => "while",
                },
                "shared-tail" => match self.shared_tail {
                    SharedTail::Goto => "goto",
                    SharedTail::Duplicate => "duplicate",
                },
                "constant-style" => match self.constant_style {
                    ConstantStyle::Mixed => "mixed",
                    ConstantStyle::Decimal => "decimal",
                    ConstantStyle::Hex => "hex",
                },
                "indent" => return Some(self.indent.to_string()),
                _ => return None,
            }
            .to_string(),
        )
    }

    /// The `(name, value)` pairs that differ from the defaults, in registry
    /// order.
    pub fn changed(&self) -> Vec<(&'static str, String)> {
        let defaults = Options::default();
        OPTIONS
            .iter()
            .filter_map(|spec| {
                let value = self.get(spec.name)?;
                (Some(&value) != defaults.get(spec.name).as_ref()).then_some((spec.name, value))
            })
            .collect()
    }

    /// The convention to lift the code of a program in `language` with.
    pub fn abi_for(&self, language: &str) -> Abi {
        match self.abi {
            AbiChoice::Auto => Abi::of_language(language),
            AbiChoice::SysV => Abi::SystemV,
            AbiChoice::Win64 => Abi::Win64,
        }
    }
}

/// The catalog as Markdown: the symptom index first, then one section per
/// phase. This is what `docs/options.md` holds.
pub fn catalog_markdown() -> String {
    let mut out = String::new();
    out.push_str("# Engine options\n\n");
    out.push_str(
        "Every judgment call the engine makes is an option, set per run with \
         `--option NAME VALUE` on `ag image <bin> pseudocode` and `ag image <bin> export`, \
         and on `ag-ui`. This file is generated by `ag catalog --markdown` from the registry \
         in `crates/ag-engine/src/options.rs`; `ag catalog --check` and `cargo test` fail \
         when it is stale. Edit the registry, not this file.\n\n",
    );

    out.push_str("## Symptom index\n\n");
    out.push_str("If the output shows… | Try…\n");
    out.push_str("--- | ---\n");
    for spec in OPTIONS {
        for symptom in spec.symptoms {
            out.push_str(&format!(
                "{} | `--option {} {}`\n",
                symptom.shows, spec.name, symptom.value
            ));
        }
    }
    out.push('\n');

    for phase in Phase::ALL {
        out.push_str(&format!("## {}\n\n", title(phase.name())));
        let rows: Vec<&OptionSpec> = OPTIONS.iter().filter(|spec| spec.phase == phase).collect();
        if rows.is_empty() {
            out.push_str("No options yet.\n\n");
            continue;
        }
        out.push_str("Option | Tier | Takes | Default | What it decides\n");
        out.push_str("--- | --- | --- | --- | ---\n");
        for spec in rows {
            out.push_str(&format!(
                "`{}` | {} | {} | `{}` | {}\n",
                spec.name,
                spec.tier.name(),
                takes(spec.kind),
                spec.default,
                spec.description
            ));
        }
        out.push('\n');
    }

    out.push_str("## Tiers\n\n");
    out.push_str(
        "A *transform* changes what statements there are; an *analysis* changes what the \
         engine concludes about the code; a *rendering* changes how the same conclusion is \
         spelled.\n",
    );
    out
}

/// The catalog as JSON: an array of rows, each with its `name`, `phase`,
/// `tier`, `type`, `default`, `description` and `symptoms`.
pub fn catalog_json() -> String {
    let mut out = String::from("[\n");
    for (i, spec) in OPTIONS.iter().enumerate() {
        out.push_str("  {\n");
        out.push_str(&format!("    \"name\": {},\n", json_string(spec.name)));
        out.push_str(&format!(
            "    \"phase\": {},\n",
            json_string(spec.phase.name())
        ));
        out.push_str(&format!(
            "    \"tier\": {},\n",
            json_string(spec.tier.name())
        ));
        match spec.kind {
            Kind::Choice(choices) => {
                let list: Vec<String> = choices.iter().map(|c| json_string(c)).collect();
                out.push_str(&format!(
                    "    \"type\": {{ \"choice\": [{}] }},\n",
                    list.join(", ")
                ));
            }
            Kind::Integer { min, max } => {
                out.push_str(&format!(
                    "    \"type\": {{ \"integer\": {{ \"min\": {min}, \"max\": {max} }} }},\n"
                ));
            }
        }
        out.push_str(&format!(
            "    \"default\": {},\n",
            json_string(spec.default)
        ));
        out.push_str(&format!(
            "    \"description\": {},\n",
            json_string(spec.description)
        ));
        out.push_str("    \"symptoms\": [\n");
        for (j, symptom) in spec.symptoms.iter().enumerate() {
            out.push_str(&format!(
                "      {{ \"shows\": {}, \"value\": {} }}{}\n",
                json_string(symptom.shows),
                json_string(symptom.value),
                if j + 1 < spec.symptoms.len() { "," } else { "" }
            ));
        }
        out.push_str("    ]\n");
        out.push_str(if i + 1 < OPTIONS.len() {
            "  },\n"
        } else {
            "  }\n"
        });
    }
    out.push_str("]\n");
    out
}

/// A string as a JSON literal.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// What a row takes, for the table: the choices in code, or the range.
fn takes(kind: Kind) -> String {
    match kind {
        Kind::Choice(choices) => choices
            .iter()
            .map(|c| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(" \\| "),
        Kind::Integer { min, max } => format!("an integer, {min} to {max}"),
    }
}

/// A word with its first letter upper-cased.
fn title(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_row_has_a_kebab_case_name_a_description_and_a_symptom() {
        let mut names: Vec<&str> = Vec::new();
        for spec in OPTIONS {
            assert!(
                spec.name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-'),
                "{} is not kebab-case",
                spec.name
            );
            assert!(!names.contains(&spec.name), "{} twice", spec.name);
            names.push(spec.name);
            assert!(
                !spec.description.is_empty(),
                "{} has no description",
                spec.name
            );
            assert!(!spec.symptoms.is_empty(), "{} has no symptoms", spec.name);
            for symptom in spec.symptoms {
                let mut options = Options::default();
                options
                    .set(spec.name, symptom.value)
                    .unwrap_or_else(|e| panic!("{}: a symptom names a bad value: {e}", spec.name));
            }
        }
        assert!(OPTIONS.len() >= 6, "the registry is seeded");
    }

    #[test]
    fn the_rows_are_in_phase_order() {
        let phases: Vec<Phase> = OPTIONS.iter().map(|spec| spec.phase).collect();
        let mut sorted = phases.clone();
        sorted.sort();
        assert_eq!(
            phases, sorted,
            "the rows are grouped by phase, in pipeline order"
        );
    }

    #[test]
    fn every_row_defaults_to_its_default_and_takes_every_value_it_lists() {
        let defaults = Options::default();
        for spec in OPTIONS {
            assert_eq!(
                defaults.get(spec.name).as_deref(),
                Some(spec.default),
                "{}: the field's default is the row's",
                spec.name
            );
            match spec.kind {
                Kind::Choice(choices) => {
                    assert!(
                        choices.contains(&spec.default),
                        "{}: the default is a choice",
                        spec.name
                    );
                    for choice in choices {
                        let mut options = Options::default();
                        options
                            .set(spec.name, choice)
                            .expect("a listed choice sets");
                        assert_eq!(options.get(spec.name).as_deref(), Some(*choice));
                    }
                }
                Kind::Integer { min, max } => {
                    for value in [min, max] {
                        let mut options = Options::default();
                        options
                            .set(spec.name, &value.to_string())
                            .expect("an in-range value sets");
                        assert_eq!(options.get(spec.name), Some(value.to_string()));
                    }
                    let mut options = Options::default();
                    assert!(options.set(spec.name, &(max + 1).to_string()).is_err());
                    assert!(options.set(spec.name, "many").is_err());
                }
            }
        }
    }

    #[test]
    fn an_unknown_name_and_a_bad_value_are_errors_that_name_the_row() {
        let mut options = Options::default();
        assert_eq!(
            options.set("loop-shape", "for").unwrap_err().to_string(),
            format!(
                "no option named \"loop-shape\"; the options are {}",
                OPTIONS
                    .iter()
                    .map(|s| s.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        );
        assert_eq!(
            options
                .set("loop-form", "sometimes")
                .unwrap_err()
                .to_string(),
            "option \"loop-form\" takes for | while, not \"sometimes\""
        );
        assert_eq!(
            options.set("indent", "9").unwrap_err().to_string(),
            "option \"indent\" takes integer 1..8, not \"9\""
        );
        assert_eq!(options.get("loop-shape"), None);
    }

    #[test]
    fn pairs_set_in_order_and_a_flat_list_pairs_up() {
        let options = Options::from_pairs([("loop-form", "while"), ("indent", "4")]).unwrap();
        assert_eq!(options.loop_form, LoopForm::While);
        assert_eq!(options.indent, 4);
        assert_eq!(
            options.changed(),
            vec![
                ("loop-form", "while".to_string()),
                ("indent", "4".to_string())
            ]
        );

        let options =
            Options::from_flat(&["constant-style", "hex", "constant-style", "decimal"]).unwrap();
        assert_eq!(options.constant_style, ConstantStyle::Decimal);
        assert_eq!(
            Options::from_flat(&["indent"]).unwrap_err().to_string(),
            "option \"indent\" was given no value"
        );
        assert!(Options::default().changed().is_empty());
    }

    #[test]
    fn the_abi_is_the_languages_unless_set() {
        let language = "x86:LE:64:default:windows";
        assert_eq!(Options::default().abi_for(language), Abi::Win64);
        assert_eq!(
            Options::default().abi_for("x86:LE:64:default:gcc"),
            Abi::SystemV
        );
        let options = Options::from_pairs([("abi", "sysv")]).unwrap();
        assert_eq!(options.abi_for(language), Abi::SystemV);
        let options = Options::from_pairs([("abi", "win64")]).unwrap();
        assert_eq!(options.abi_for("x86:LE:64:default:gcc"), Abi::Win64);
    }

    #[test]
    fn the_markdown_opens_with_the_symptom_index_and_has_a_section_per_phase() {
        let markdown = catalog_markdown();
        let index = markdown.find("## Symptom index").expect("the index");
        for phase in Phase::ALL {
            let heading = format!("\n## {}\n", title(phase.name()));
            let at = markdown
                .find(&heading)
                .unwrap_or_else(|| panic!("{heading}"));
            assert!(at > index, "the index comes before {heading}");
        }
        assert!(markdown.contains("| `--option loop-form while`\n"));
        assert!(markdown.contains("`loop-form` | transform | `for` \\| `while` | `for` |"));
        assert!(markdown.contains("## Decode\n\nNo options yet."));
    }

    #[test]
    fn the_json_is_one_object_per_row() {
        let json = catalog_json();
        assert!(json.starts_with("[\n  {\n    \"name\": \"abi\",\n"));
        assert_eq!(json.matches("\"name\": ").count(), OPTIONS.len());
        assert!(json.contains("\"type\": { \"choice\": [\"for\", \"while\"] }"));
        assert!(json.contains("\"type\": { \"integer\": { \"min\": 1, \"max\": 8 } }"));
        assert!(json.contains(
            "{ \"shows\": \"`0x64` where the source said `100`\", \"value\": \"decimal\" }"
        ));
        assert_eq!(json_string("a \"b\"\n"), "\"a \\\"b\\\"\\n\"");
    }
}
