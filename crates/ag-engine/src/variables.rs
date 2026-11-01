//! The variables of a lifted function, with where each lives.
//!
//! Every parameter and local the function declares is listed once, in the
//! order of its declaration — the parameters first — with its type, the
//! places it lives ([`Placement`]) and the statements that assign and read
//! it. The lift records the placement where it makes the variable: a
//! parameter lives in its argument register at the width it is read at, a
//! stack slot at its offset from the stack pointer at entry, a register two
//! paths leave different in that register, a call's result in the
//! accumulator. A variable an inlined callee brings keeps its place in the
//! callee's frame, marked as the callee's; the piece a split or a new
//! version makes lives where its origin does, and the variable a merge
//! keeps lives where both did.

use crate::lift::{LiftedFunction, Placement};
use crate::slice::Graph;

/// Whether a variable is a parameter or a local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableKind {
    /// A parameter.
    Param,
    /// A local.
    Local,
}

impl VariableKind {
    /// The kind as the variables listing names it: `param`, `local`.
    pub fn name(self) -> &'static str {
        match self {
            VariableKind::Param => "param",
            VariableKind::Local => "local",
        }
    }
}

/// One variable of a lifted function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableInfo {
    /// The name shown for it: the lift's, until the analyst's rename takes
    /// its place.
    pub name: String,
    /// The name the lift declares it by, which the analyst's words key on.
    pub lift_name: String,
    /// The C type; for a variable that holds bytes of a structure, the
    /// structure and the bytes, `struct point [4..8) (y)`
    /// ([`crate::lift::Variable::shown_type`]).
    pub ty: String,
    /// Whether it is a parameter or a local.
    pub kind: VariableKind,
    /// Where it lives.
    pub placements: Vec<Placement>,
    /// The first address of each statement that assigns it, in the order
    /// the body reads; two statements from one instruction give it twice.
    pub defined_at: Vec<u64>,
    /// The first address of each statement that reads it, in the same
    /// order.
    pub used_at: Vec<u64>,
}

impl VariableInfo {
    /// The placements as the listing spells them, joined by `; `; `-` for
    /// a variable the lift says nothing of.
    pub fn placement_text(&self) -> String {
        if self.placements.is_empty() {
            return "-".to_string();
        }
        self.placements
            .iter()
            .map(Placement::spelled)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl LiftedFunction {
    /// The function's parameters and locals, as its body reads now: the
    /// analyst's merges, splits and versions made.
    pub fn variables(&self) -> Vec<VariableInfo> {
        let graph = Graph::of(self);
        let sites = |name: &str| -> (Vec<u64>, Vec<u64>) {
            let (mut defined, mut used) = (Vec::new(), Vec::new());
            let Some(&var) = graph.vars.get(name) else {
                return (defined, used);
            };
            for node in &graph.nodes {
                // The entry gives every variable its value on entry, and
                // is no statement.
                let (Some(_), Some(&first)) = (node.owner, node.addresses.first()) else {
                    continue;
                };
                if node.defs.iter().any(|&(d, kills)| d == var && kills) {
                    defined.push(first);
                }
                if node.uses.contains(&var) {
                    used.push(first);
                }
            }
            // A store into a part of the variable — an element of an
            // analyst's array, the bytes at an offset into it — assigns it
            // too, though as memory it stays live.
            defined.extend(parts_stored(&self.body, name));
            defined.sort_unstable();
            defined.dedup();
            (defined, used)
        };
        let kinds = self
            .params
            .iter()
            .map(|v| (v, VariableKind::Param))
            .chain(self.locals.iter().map(|v| (v, VariableKind::Local)));
        kinds
            .map(|(variable, kind)| {
                let (defined_at, used_at) = sites(&variable.name);
                VariableInfo {
                    name: variable.name.clone(),
                    lift_name: variable.name.clone(),
                    ty: variable.shown_type(),
                    kind,
                    placements: variable.placements.clone(),
                    defined_at,
                    used_at,
                }
            })
            .collect()
    }
}

/// The first addresses of the statements of `statements` that store into
/// a part of `name`: `name[2] = …`, `*(int *)((char *)&name + 4) = …`.
fn parts_stored(statements: &[crate::lift::Statement], name: &str) -> Vec<u64> {
    use crate::ast::AstNode;
    use crate::lift::StatementKind;
    let into = |node: &AstNode| match node {
        AstNode::Assign { lhs, .. } => match crate::slice::strip_casts(lhs) {
            AstNode::Var { .. } => false,
            target => target.any(&|n| match n {
                AstNode::AddressOf { target } => {
                    matches!(target.as_ref(), AstNode::Var { name: held } if held == name)
                }
                n => crate::stack_vars::is_part(n) && crate::stack_vars::part_root(n) == Some(name),
            }),
        },
        _ => false,
    };
    let mut found = Vec::new();
    for statement in statements {
        if let StatementKind::For { init, step, .. } = &statement.kind {
            for part in [init, step] {
                if into(&part.node) {
                    found.extend(part.addresses.first());
                }
            }
        }
        if into(&statement.node) {
            found.extend(statement.addresses.first());
        }
        for child in statement.children() {
            found.extend(parts_stored(child, name));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu_context::X86IcedContext;
    use crate::lift::{lift_block, Abi, Symbols, Variable};
    use crate::options::Options;
    use crate::pipeline::Disasm;

    const BASE: u64 = 0x1000;

    fn names(address: u64) -> Option<String> {
        (address == 0x2000).then(|| "g".to_string())
    }

    fn lift_with(bytes: &[u8], symbols: &dyn Symbols) -> LiftedFunction {
        let mut ctx = X86IcedContext::default();
        let instructions = Disasm::decode(&mut ctx, bytes, BASE)
            .expect("the code decodes")
            .instructions;
        lift_block(
            &instructions,
            BASE,
            "f",
            Abi::SystemV,
            symbols,
            &Options::default(),
        )
        .expect("the code lifts")
    }

    fn lift(bytes: &[u8]) -> LiftedFunction {
        lift_with(bytes, &names)
    }

    fn register(name: &str, full: &str) -> Placement {
        Placement::Register {
            name: name.to_string(),
            full: full.to_string(),
        }
    }

    fn info<'a>(variables: &'a [VariableInfo], name: &str) -> &'a VariableInfo {
        variables
            .iter()
            .find(|v| v.lift_name == name)
            .unwrap_or_else(|| panic!("no {name} among {variables:?}"))
    }

    #[test]
    fn a_parameter_lives_in_its_argument_register_at_its_width() {
        // mov eax, edi; add eax, esi; ret
        let function = lift(&[0x89, 0xf8, 0x01, 0xf0, 0xc3]);
        let variables = function.variables();
        let a = info(&variables, "a");
        assert_eq!(a.kind, VariableKind::Param);
        assert_eq!(a.placements, vec![register("edi", "rdi")]);
        assert_eq!(a.placement_text(), "edi (in rdi)");
        assert_eq!(a.used_at, vec![0x1000]);
        assert!(a.defined_at.is_empty());
        let b = info(&variables, "b");
        assert_eq!(b.placement_text(), "esi (in rsi)");
    }

    #[test]
    fn a_64_bit_parameter_is_the_whole_register() {
        // mov rax, rdi; ret
        let function = lift(&[0x48, 0x89, 0xf8, 0xc3]);
        assert_eq!(function.variables()[0].placement_text(), "rdi");
    }

    #[test]
    fn a_stack_local_lives_at_its_offset_from_the_entry_stack_pointer() {
        // mov [rsp-0x14], edi; lea rax, [rsp-0x14]; ret: the slot's address
        // is taken, so it is a declared local.
        let function = lift(&[0x89, 0x7c, 0x24, 0xec, 0x48, 0x8d, 0x44, 0x24, 0xec, 0xc3]);
        let variables = function.variables();
        let local = info(&variables, "local_14");
        assert_eq!(local.kind, VariableKind::Local);
        assert_eq!(
            local.placements,
            vec![Placement::Stack {
                offset: -0x14,
                size: 4
            }]
        );
        assert_eq!(local.placement_text(), "[sp-0x14] 4 bytes");
        assert_eq!(local.defined_at, vec![0x1000]);
    }

    #[test]
    fn a_value_saved_before_its_slot_changes_is_a_temporary() {
        // mov eax, [rsp-8]; mov [rsp-16], eax; mov dword [rsp-8], 5;
        // mov eax, [rsp-16]; ret: `v1 = local_8; local_8 = 5; return v1;`
        let function = lift(&[
            0x8b, 0x44, 0x24, 0xf8, 0x89, 0x44, 0x24, 0xf0, 0xc7, 0x44, 0x24, 0xf8, 5, 0, 0, 0,
            0x8b, 0x44, 0x24, 0xf0, 0xc3,
        ]);
        let variables = function.variables();
        assert_eq!(
            info(&variables, "local_8").placement_text(),
            "[sp-0x8] 4 bytes"
        );
        let saved = info(&variables, "v1");
        assert_eq!(saved.placements, vec![Placement::Temporary]);
        assert_eq!(saved.defined_at.len(), 1);
        assert_eq!(saved.used_at.len(), 1);
    }

    #[test]
    fn a_register_two_paths_leave_different_lives_in_that_register() {
        // test edi, edi; je +7; mov eax, 1; jmp +5; mov eax, 2; ret
        let function = lift(&[
            0x85, 0xff, 0x74, 0x07, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xb8, 0x02, 0x00,
            0x00, 0x00, 0xc3,
        ]);
        let variables = function.variables();
        let eax = variables
            .iter()
            .find(|v| v.kind == VariableKind::Local)
            .unwrap_or_else(|| panic!("a register variable among {variables:?}"));
        assert_eq!(eax.placement_text(), "eax (in rax)");
        assert_eq!(eax.defined_at.len(), 2, "{eax:?}");
    }

    #[test]
    fn a_call_result_kept_lives_in_the_accumulator() {
        // call g; mov ebx, eax; call sub_3000; add eax, ebx; ret:
        // `v1 = g(); return sub_3000() + v1;`
        let function = lift(&[
            0xe8, 0xfb, 0x0f, 0x00, 0x00, 0x89, 0xc3, 0xe8, 0xf4, 0x1f, 0x00, 0x00, 0x01, 0xd8,
            0xc3,
        ]);
        let variables = function.variables();
        let result = info(&variables, "v1");
        assert_eq!(result.placement_text(), "eax (in rax)");
        assert_eq!(result.defined_at, vec![0x1000]);
    }

    #[test]
    fn the_flag_spelling_is_the_flag_and_a_temporary_says_so() {
        assert_eq!(Placement::Flag("zf".to_string()).spelled(), "zf");
        assert_eq!(Placement::Temporary.spelled(), "temporary");
        assert_eq!(
            Placement::Stack { offset: 8, size: 1 }.spelled(),
            "[sp+0x8] 1 byte"
        );
        assert_eq!(
            register("rdi", "rdi").inlined_from("g").spelled(),
            "rdi, inlined from g"
        );
    }

    /// A function `f(a)` over hand-made statements, its variables placed.
    fn made(locals: Vec<Variable>, body: Vec<crate::lift::Statement>) -> LiftedFunction {
        LiftedFunction {
            name: "f".to_string(),
            address: 0x1000,
            return_type: "int".to_string(),
            params: vec![Variable::new("int", "a").placed(register("edi", "rdi"))],
            locals,
            body,
            frame: Vec::new(),
            notes: Vec::new(),
            call_notes: Vec::new(),
            noreturn_when: Vec::new(),
            thunk: None,
            return_reason: None,
        }
    }

    fn assign(to: &str, value: crate::ast::AstNode, at: u64) -> crate::lift::Statement {
        crate::lift::Statement::plain(
            crate::ast::AstNode::Assign {
                lhs: Box::new(crate::ast::AstNode::var(to)),
                rhs: Box::new(value),
            },
            vec![at],
        )
    }

    fn ret(name: &str, at: u64) -> crate::lift::Statement {
        crate::lift::Statement::plain(
            crate::ast::AstNode::Return {
                value: Some(Box::new(crate::ast::AstNode::var(name))),
            },
            vec![at],
        )
    }

    #[test]
    fn a_merged_variable_lives_where_both_did() {
        use crate::ast::AstNode;
        let slot = Placement::Stack {
            offset: -0x14,
            size: 4,
        };
        let mut function = made(
            vec![
                Variable::new("int", "eax").placed(register("eax", "rax")),
                Variable::new("int", "local_14").placed(slot.clone()),
            ],
            vec![
                assign("eax", AstNode::var("a"), 0x1000),
                assign("local_14", AstNode::var("eax"), 0x1004),
                ret("local_14", 0x1008),
            ],
        );
        crate::merge::apply_merges(
            &mut function,
            &[("eax".to_string(), "local_14".to_string())],
        );
        let variables = function.variables();
        assert_eq!(variables.len(), 2, "{variables:?}");
        let eax = info(&variables, "eax");
        assert_eq!(eax.placements, vec![register("eax", "rax"), slot]);
        assert_eq!(eax.placement_text(), "eax (in rax); [sp-0x14] 4 bytes");
    }

    #[test]
    fn a_split_piece_lives_where_its_origin_does() {
        use crate::ast::AstNode;
        let mut function = made(
            vec![Variable::new("int", "eax").placed(register("eax", "rax"))],
            vec![
                assign("eax", AstNode::var("a"), 0x1000),
                assign("a", AstNode::var("eax"), 0x1004),
                assign("eax", AstNode::constant(5, 4), 0x1008),
                ret("eax", 0x100c),
            ],
        );
        crate::merge::apply_splits(&mut function, &[("eax".to_string(), 0x1008)]);
        let variables = function.variables();
        let piece = info(&variables, "eax_2");
        assert_eq!(piece.placement_text(), "eax (in rax)");
        assert_eq!(piece.defined_at, vec![0x1008]);
        assert_eq!(piece.used_at, vec![0x100c]);
        crate::merge::apply_versions(&mut function, &[("eax".to_string(), 0x1004)]);
        let variables = function.variables();
        let version = info(&variables, "eax_3");
        assert_eq!(version.kind, VariableKind::Local);
        assert_eq!(version.placement_text(), "eax (in rax)", "{variables:?}");
    }

    #[test]
    fn an_inlined_callee_s_variables_keep_their_place_in_its_frame() {
        // The callee g at 0x2000: lea eax, [rdi+1]... written so its
        // parameter is read twice and so is bound to a local:
        // mov eax, edi; imul eax, edi; ret
        struct Inlining;
        impl Symbols for Inlining {
            fn function_name(&self, address: u64) -> Option<String> {
                names(address)
            }
            fn inline_body(&self, address: u64) -> Option<Result<LiftedFunction, String>> {
                (address == 0x2000).then(|| {
                    let mut ctx = X86IcedContext::default();
                    let instructions =
                        Disasm::decode(&mut ctx, &[0x89, 0xf8, 0x0f, 0xaf, 0xc7, 0xc3], 0x2000)
                            .expect("the code decodes")
                            .instructions;
                    lift_block(
                        &instructions,
                        0x2000,
                        "g",
                        Abi::SystemV,
                        &names,
                        &Options::default(),
                    )
                    .map_err(|error| error.to_string())
                })
            }
        }
        // f: lea edi, [rdi+1]; call g; ret — the argument is an
        // expression read twice, so it is bound to `g_a`.
        let call = (0x2000i64 - 0x1008) as i32;
        let mut bytes = vec![0x8d, 0x7f, 0x01, 0xe8];
        bytes.extend(call.to_le_bytes());
        bytes.push(0xc3);
        let function = lift_with(&bytes, &Inlining);
        let variables = function.variables();
        let bound = variables
            .iter()
            .find(|v| v.lift_name.starts_with("g_"))
            .unwrap_or_else(|| {
                panic!(
                    "the callee's parameter among {variables:?}: {}",
                    crate::emit::emit_function(&function, &Options::default()).text()
                )
            });
        assert_eq!(
            bound.placements,
            vec![register("edi", "rdi").inlined_from("g")],
            "{variables:?}"
        );
        assert_eq!(bound.placement_text(), "edi (in rdi), inlined from g");
    }
}
