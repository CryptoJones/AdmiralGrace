//! The stack frame of a lifted function, slot by slot.
//!
//! The lift tracks the stack pointer as an offset from its value at the
//! function's entry, and keys every stack slot the code reads or writes by
//! that offset, as its `local_14` names count it. The frame is read off
//! what the walk saw: every access to a slot with its width, the slots a
//! register's value on entry is stored into, the slots whose address is
//! taken, and the prologue's `sub rsp, N`.
//!
//! Each slot is a row, from the top of the frame down:
//!
//! - **caller**: at `+0x8` and above, the caller's frame — the arguments
//!   passed on the stack, and the home area a Microsoft x64 caller leaves
//!   for the register arguments;
//! - **return address**: the 8 bytes at `+0x0` the `call` pushed;
//! - **saved**: a slot a register's value on entry is stored into — the
//!   pushes of the prologue, `push rbp`, `push rbx` — named by the register,
//!   `saved rbx`;
//! - **local**: the slots below, the function's own.
//!
//! A row says the sizes the code accesses the slot at — the widest is its
//! size — the variable it belongs to, a lifted local or parameter whose
//! stack placement holds it or a variable the analyst made around it, and
//! whether its address is taken. The bytes the code never touches between
//! the lowest point of the frame and the return address, and between the
//! caller's slots, are gaps, so the layout reads as one contiguous frame.
//! The lowest point is the lowest of the stack pointer and the slots.

use std::collections::{BTreeMap, BTreeSet};

use crate::lift::{Placement, Stages};
use crate::stack_vars::StackVar;

/// What the lift saw of a function's stack frame as it walked the code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlotFacts {
    /// The accesses to stack slots: the slot's offset from the entry's
    /// stack pointer, the bytes accessed, and the instruction's address.
    pub accesses: BTreeSet<(i64, u32, u64)>,
    /// The slots a register's value on entry is stored into, by offset: the
    /// register, `rbx`.
    pub saved: BTreeMap<i64, String>,
    /// The slots whose address is taken.
    pub address_taken: BTreeSet<i64>,
    /// `N` of the prologue's `sub rsp, N`, when there is one.
    pub frame_size: Option<u64>,
    /// The analyst's variables the lift made, with their names and types.
    pub made: Vec<StackVar>,
}

/// The region of the frame a row is in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Region {
    /// At `+0x8` and above: the caller's frame.
    Caller,
    /// The return address at `+0x0`.
    ReturnAddress,
    /// A register's value on entry, saved: the register.
    Saved(String),
    /// The function's own slots, below the return address.
    Local,
}

impl Region {
    /// The region as the frame's listing spells it: `caller`, `return
    /// address`, `saved rbx`, `local`.
    pub fn spelled(&self) -> String {
        match self {
            Region::Caller => "caller".to_string(),
            Region::ReturnAddress => "return address".to_string(),
            Region::Saved(register) => format!("saved {register}"),
            Region::Local => "local".to_string(),
        }
    }

    /// The region's kind, without the register: `caller`, `return`,
    /// `saved`, `local`.
    pub fn kind(&self) -> &'static str {
        match self {
            Region::Caller => "caller",
            Region::ReturnAddress => "return",
            Region::Saved(_) => "saved",
            Region::Local => "local",
        }
    }
}

/// One row of a stack frame: a slot the code touches, or a gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRow {
    /// The offset from the stack pointer at the function's entry.
    pub offset: i64,
    /// The size in bytes: the widest access, or the gap's length.
    pub size: u32,
    /// The region the row is in.
    pub region: Region,
    /// The sizes the code accesses the slot at, least first; none for a
    /// gap.
    pub sizes: Vec<u32>,
    /// The variable the slot belongs to, by the name the lift declares, and
    /// its type.
    pub variable: Option<(String, String)>,
    /// Whether the variable is one the analyst made.
    pub analyst: bool,
    /// Whether the slot's address is taken.
    pub address_taken: bool,
    /// Whether the row is bytes the code never touches.
    pub gap: bool,
    /// The addresses of the instructions that access the slot.
    pub accessed_at: Vec<u64>,
}

impl FrameRow {
    /// The row's offset as the frame's listing spells it: `+0x8`, `-0x14`.
    pub fn offset_text(&self) -> String {
        let sign = if self.offset < 0 { '-' } else { '+' };
        format!("{sign}{:#x}", self.offset.unsigned_abs())
    }

    /// The row's place, as a variable's placement spells it: `[sp-0x14] 4
    /// bytes`.
    pub fn placement(&self) -> Placement {
        Placement::Stack {
            offset: self.offset,
            size: self.size,
        }
    }
}

/// A function's stack frame, from the top down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFrame {
    /// The function's name.
    pub function: String,
    /// The function's entry address.
    pub address: u64,
    /// `N` of the prologue's `sub rsp, N`, when there is one.
    pub frame_size: Option<u64>,
    /// The lowest the stack pointer goes below its value at entry, in
    /// bytes: the pushes and the `sub rsp` together.
    pub depth: u64,
    /// The rows, the highest offset first.
    pub rows: Vec<FrameRow>,
}

/// The stack frame of the function `stages` lifted.
pub fn stack_frame(stages: &Stages) -> StackFrame {
    let function = &stages.function;
    let facts = &stages.slots;
    let depth = stages
        .stack_pointer
        .values()
        .copied()
        .min()
        .unwrap_or(0)
        .min(0)
        .unsigned_abs();
    // The variables that live on the stack, by their extents.
    let mut variables: Vec<(i64, i64, String, String, bool)> = Vec::new();
    for variable in function.params.iter().chain(&function.locals) {
        for placement in &variable.placements {
            if let Placement::Stack { offset, size } = placement {
                let analyst = facts
                    .made
                    .iter()
                    .any(|made| made.name.as_deref() == Some(variable.name.as_str()));
                variables.push((
                    *offset,
                    *offset + i64::from(*size),
                    variable.name.clone(),
                    variable.ty.clone(),
                    analyst,
                ));
            }
        }
    }
    let variable_at = |offset: i64, end: i64| {
        variables
            .iter()
            .filter(|(start, stop, ..)| *start <= offset && offset < *stop)
            .min_by_key(|(start, stop, ..)| (*start != offset || *stop != end, stop - start))
    };
    let region_of = |offset: i64| {
        if offset >= 8 {
            Region::Caller
        } else if offset >= 0 {
            Region::ReturnAddress
        } else if let Some(register) = facts.saved.get(&offset) {
            Region::Saved(register.clone())
        } else {
            Region::Local
        }
    };
    // The slots, by offset: the sizes and the instructions.
    let mut slots: BTreeMap<i64, (BTreeSet<u32>, BTreeSet<u64>)> = BTreeMap::new();
    for &(offset, size, at) in &facts.accesses {
        let slot = slots.entry(offset).or_default();
        slot.0.insert(size.max(1));
        slot.1.insert(at);
    }
    for &offset in &facts.address_taken {
        slots.entry(offset).or_default();
    }
    let mut rows: Vec<FrameRow> = Vec::new();
    for (offset, (sizes, at)) in &slots {
        let size = sizes.iter().copied().max().unwrap_or_else(|| {
            // An address taken and never read here: as wide as its
            // variable, or a byte.
            variable_at(*offset, *offset)
                .map(|(start, stop, ..)| (stop - offset).min(stop - start) as u32)
                .unwrap_or(1)
        });
        let variable = variable_at(*offset, offset + i64::from(size));
        // The return address is the return address, whatever reads it.
        let region = if (0..8).contains(offset) {
            Region::ReturnAddress
        } else {
            region_of(*offset)
        };
        rows.push(FrameRow {
            offset: *offset,
            size,
            region,
            sizes: sizes.iter().copied().collect(),
            variable: variable.map(|(.., name, ty, _)| (name.clone(), ty.clone())),
            analyst: variable.is_some_and(|(.., analyst)| *analyst),
            address_taken: facts.address_taken.contains(offset)
                || variable.is_some_and(|(start, stop, ..)| {
                    facts
                        .address_taken
                        .iter()
                        .any(|taken| start <= taken && taken < stop)
                }),
            gap: false,
            accessed_at: at.iter().copied().collect(),
        });
    }
    if !rows.iter().any(|row| row.offset == 0) && function.thunk.is_none() {
        rows.push(FrameRow {
            offset: 0,
            size: 8,
            region: Region::ReturnAddress,
            sizes: Vec::new(),
            variable: None,
            analyst: false,
            address_taken: false,
            gap: false,
            accessed_at: Vec::new(),
        });
    }
    // The analyst's variables the code never touches are rows of their own.
    for (start, stop, name, ty, analyst) in &variables {
        if *analyst
            && !rows
                .iter()
                .any(|row| *start <= row.offset && row.offset < *stop)
        {
            rows.push(FrameRow {
                offset: *start,
                size: (stop - start) as u32,
                region: region_of(*start),
                sizes: Vec::new(),
                variable: Some((name.clone(), ty.clone())),
                analyst: true,
                address_taken: false,
                gap: false,
                accessed_at: Vec::new(),
            });
        }
    }
    // The gaps: the bytes nothing covers, from the lowest point of the
    // frame to the top of the highest slot.
    let covered: Vec<(i64, i64)> = rows
        .iter()
        .map(|row| (row.offset, row.offset + i64::from(row.size)))
        .collect();
    let bottom = covered
        .iter()
        .map(|(start, _)| *start)
        .min()
        .unwrap_or(0)
        .min(-(depth as i64));
    let top = covered
        .iter()
        .map(|(_, end)| *end)
        .max()
        .unwrap_or(8)
        .max(8);
    let mut gaps = Vec::new();
    let mut at = bottom;
    while at < top {
        let holding = covered
            .iter()
            .filter(|(start, end)| *start <= at && at < *end)
            .map(|(_, end)| *end)
            .max();
        match holding {
            Some(end) => at = end,
            None => {
                let next = covered
                    .iter()
                    .map(|(start, _)| *start)
                    .filter(|start| *start > at)
                    .min()
                    .unwrap_or(top);
                // A gap does not run across the return address.
                let next = if at < 0 { next.min(0) } else { next };
                let variable = variable_at(at, next);
                gaps.push(FrameRow {
                    offset: at,
                    size: (next - at) as u32,
                    region: region_of(at),
                    sizes: Vec::new(),
                    variable: variable.map(|(.., name, ty, _)| (name.clone(), ty.clone())),
                    analyst: variable.is_some_and(|(.., analyst)| *analyst),
                    address_taken: false,
                    gap: true,
                    accessed_at: Vec::new(),
                });
                at = next;
            }
        }
    }
    rows.extend(gaps);
    rows.sort_by(|a, b| b.offset.cmp(&a.offset).then(b.size.cmp(&a.size)));
    StackFrame {
        function: function.name.clone(),
        address: function.address,
        frame_size: facts.frame_size,
        depth,
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Bitness;
    use crate::cfgwalk::{resolve_branches_among, NoEntries};
    use crate::cpu_context::X86IcedContext;
    use crate::emit::emit_function;
    use crate::lift::{lift_stages, Abi, Symbols};
    use crate::merge::VariableEdits;
    use crate::options::Options;
    use crate::pipeline::Disasm;

    const BASE: u64 = 0x1000;

    /// The analyst's stack variables, as the image would give them.
    struct Words(Vec<StackVar>);

    impl Symbols for Words {
        fn function_name(&self, _address: u64) -> Option<String> {
            None
        }

        fn variable_edits(&self, _address: u64) -> VariableEdits {
            VariableEdits {
                stack_vars: self.0.clone(),
                ..VariableEdits::default()
            }
        }
    }

    /// The stages of `bytes` lifted as `f`, with the analyst's `words`.
    fn stages(bytes: &[u8], words: &[StackVar]) -> Stages {
        let mut ctx = X86IcedContext::default();
        let disasm = Disasm::decode(&mut ctx, bytes, BASE).expect("the code decodes");
        let cfg = resolve_branches_among(&disasm, BASE, &NoEntries);
        lift_stages(
            &disasm,
            &cfg,
            BASE,
            "f",
            Bitness::Bits64,
            Abi::SystemV,
            &Words(words.to_vec()),
            &Options::default(),
        )
        .expect("the code lifts")
    }

    /// The pseudocode of `bytes` with the analyst's `words`, without the
    /// comment saying what decided the return type.
    fn c(bytes: &[u8], words: &[StackVar]) -> String {
        emit_function(&stages(bytes, words).function, &Options::default())
            .lines
            .iter()
            .map(|line| line.text.as_str())
            .filter(|text| !(text.starts_with("// void: ") || text.starts_with("// returns ")))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn word(offset: i64, size: u32, name: &str, ty: &str) -> StackVar {
        StackVar {
            offset,
            size,
            name: (!name.is_empty()).then(|| name.to_string()),
            ty: (!ty.is_empty()).then(|| ty.to_string()),
        }
    }

    /// A row as `(offset, size, region, variable, address taken, gap)`.
    fn rows(frame: &StackFrame) -> Vec<(i64, u32, String, Option<String>, bool, bool)> {
        frame
            .rows
            .iter()
            .map(|row| {
                (
                    row.offset,
                    row.size,
                    row.region.spelled(),
                    row.variable
                        .as_ref()
                        .map(|(name, ty)| format!("{ty} {name}")),
                    row.address_taken,
                    row.gap,
                )
            })
            .collect()
    }

    /// push rbp; mov rbp, rsp; push rbx; sub rsp, 0x28;
    /// mov [rbp-0x14], edi; mov rax, [rbp+0x10]; mov [rbp-0x20], rax;
    /// lea rax, [rbp-0x30]; add rsp, 0x28; pop rbx; pop rbp; ret
    const FRAMED: [u8; 31] = [
        0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x83, 0xec, 0x28, 0x89, 0x7d, 0xec, 0x48, 0x8b, 0x45,
        0x10, 0x48, 0x89, 0x45, 0xe0, 0x48, 0x8d, 0x45, 0xd0, 0x48, 0x83, 0xc4, 0x28, 0x5b, 0x5d,
        0xc3,
    ];

    #[test]
    fn the_frame_reads_the_prologue_the_locals_the_callers_slot_and_the_gaps() {
        let frame = stack_frame(&stages(&FRAMED, &[]));
        assert_eq!(frame.frame_size, Some(0x28));
        assert_eq!(frame.depth, 0x38);
        let row = |offset, size, region: &str, variable: Option<&str>, taken, gap| {
            (
                offset,
                size,
                region.to_string(),
                variable.map(str::to_string),
                taken,
                gap,
            )
        };
        assert_eq!(
            rows(&frame),
            vec![
                row(0x8, 8, "caller", Some("long stack_8"), false, false),
                row(0x0, 8, "return address", None, false, false),
                row(-0x8, 8, "saved rbp", None, false, false),
                row(-0x10, 8, "saved rbx", None, false, false),
                row(-0x18, 8, "local", None, false, true),
                row(-0x1c, 4, "local", None, false, false),
                row(-0x20, 4, "local", None, false, true),
                row(-0x28, 8, "local", None, false, false),
                row(-0x30, 8, "local", None, false, true),
                row(-0x38, 8, "local", Some("long local_38"), true, false),
            ]
        );
        // The rows run without a hole from the bottom to the caller's slot.
        for pair in frame.rows.windows(2) {
            assert_eq!(
                pair[1].offset + i64::from(pair[1].size),
                pair[0].offset,
                "{pair:?}"
            );
        }
        assert_eq!(frame.rows[0].offset_text(), "+0x8");
        assert_eq!(frame.rows[5].offset_text(), "-0x1c");
        assert_eq!(frame.rows[5].sizes, [4]);
        assert_eq!(frame.rows[5].accessed_at, [0x1009]);
    }

    /// push rbp; mov rbp, rsp; mov dword [rbp-0x10], 1;
    /// mov dword [rbp-0xc], 2; mov eax, [rbp-0x10]; add eax, [rbp-0xc];
    /// pop rbp; ret
    const PAIR: [u8; 25] = [
        0x55, 0x48, 0x89, 0xe5, 0xc7, 0x45, 0xf0, 0x01, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xf4, 0x02,
        0x00, 0x00, 0x00, 0x8b, 0x45, 0xf0, 0x03, 0x45, 0xf4, 0x5d,
    ];

    fn pair_code() -> Vec<u8> {
        let mut code = PAIR.to_vec();
        code.push(0xc3);
        code
    }

    #[test]
    fn an_array_over_two_slots_reads_as_one_variable_with_elements() {
        let code = pair_code();
        // The lift's own reading: the two slots are values, propagated.
        let own = c(&code, &[]);
        assert!(!own.contains("local_"), "{own}");
        let made = c(&code, &[word(-0x18, 8, "pair", "int[2]")]);
        assert_eq!(
            made,
            "int f(void)\n{\n  int pair[2];\n\n  pair[0] = 1;\n  pair[1] = 2;\n  return pair[0] + pair[1];\n}"
        );
        let stages = stages(&code, &[word(-0x18, 8, "pair", "int[2]")]);
        let pair = &stages.function.locals[0];
        assert_eq!(
            pair.placements,
            [Placement::Stack {
                offset: -0x18,
                size: 8
            }]
        );
        let frame = stack_frame(&stages);
        let inside: Vec<(i64, bool)> = frame
            .rows
            .iter()
            .filter(|row| {
                row.variable
                    .as_ref()
                    .is_some_and(|(name, _)| name == "pair")
            })
            .map(|row| (row.offset, row.analyst))
            .collect();
        assert_eq!(inside, [(-0x14, true), (-0x18, true)]);
        // Taken back, the lift's own reading again.
        assert_eq!(c(&code, &[]), own);

        // Two of the lift's locals, read before they are written, are one
        // array's elements.
        // mov eax, [rsp-8]; add eax, [rsp-4]; ret
        let code = [0x8b, 0x44, 0x24, 0xf8, 0x03, 0x44, 0x24, 0xfc, 0xc3];
        assert_eq!(
            c(&code, &[]),
            "int f(void)\n{\n  int local_4;\n  int local_8;\n\n  return local_8 + local_4;\n}"
        );
        assert_eq!(
            c(&code, &[word(-8, 8, "pair", "int[]")]),
            "int f(void)\n{\n  int pair[2];\n\n  return pair[0] + pair[1];\n}"
        );
    }

    #[test]
    fn a_variable_of_no_known_type_reads_its_slots_at_byte_offsets() {
        let made = c(&pair_code(), &[word(-0x18, 8, "", "struct pair")]);
        assert_eq!(
            made,
            "int f(void)\n{\n  struct pair local_18;\n\n  *(int *)&local_18 = 1;\n  *(int *)((char *)&local_18 + 4) = 2;\n  return *(int *)&local_18 + *(int *)((char *)&local_18 + 4);\n}"
        );
    }

    #[test]
    fn a_variable_of_a_lifted_locals_width_replaces_it() {
        // mov eax, [rsp-8]; ret
        let code = [0x8b, 0x44, 0x24, 0xf8, 0xc3];
        assert_eq!(
            c(&code, &[]),
            "int f(void)\n{\n  int local_8;\n\n  return local_8;\n}"
        );
        assert_eq!(
            c(&code, &[word(-8, 4, "n", "unsigned int")]),
            "int f(void)\n{\n  unsigned int n;\n\n  return n;\n}"
        );
        // Unnamed and untyped, it is named and typed as the lift's.
        assert_eq!(
            c(&code, &[word(-8, 4, "", "")]),
            "int f(void)\n{\n  int local_8;\n\n  return local_8;\n}"
        );
    }

    #[test]
    fn an_overlapping_variable_is_refused_with_a_note() {
        let text = c(
            &pair_code(),
            &[word(-0x18, 8, "pair", "int[2]"), word(-0x14, 4, "x", "")],
        );
        assert!(
            text.starts_with(
                "// x is not made at [sp-0x14] 4 bytes: it overlaps pair at [sp-0x18] 8 bytes\n"
            ),
            "{text}"
        );
        assert!(text.contains("pair[1] = 2;"), "{text}");
        assert!(!text.contains("int x;"), "{text}");
    }

    #[test]
    fn a_variable_named_as_another_of_the_function_is_refused() {
        // mov eax, edi; mov [rsp-8], eax; mov eax, [rsp-8]; ret: `a` is the
        // parameter's name.
        let code = [
            0x89, 0xf8, 0x89, 0x44, 0x24, 0xf8, 0x8b, 0x44, 0x24, 0xf8, 0xc3,
        ];
        let text = c(&code, &[word(-8, 4, "a", "")]);
        assert!(
            text.starts_with("// a is not made at [sp-0x8] 4 bytes: f declares a already\n"),
            "{text}"
        );
    }
}
