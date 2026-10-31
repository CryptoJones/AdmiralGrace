//! Lifted functions as C++ that compiles: the medium level — statements
//! over variables on the block graph — written out with a label per block
//! and a `goto` for every way out, the image's globals and imports
//! declared, and a `main` that calls one function with the arguments on
//! its command line, so a lifter's reading of the machine can be built
//! with a compiler and run beside the program it came from. The spelling
//! is the pseudocode's: the lift's own types and casts, which are C.

use std::collections::BTreeSet;

use crate::ast::AstNode;
use crate::lift::Stages;
use crate::structure::Terminator;

/// A function the program declares and does not define: an import, or a
/// function the lifter refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct External {
    pub name: String,
    /// Why there is no body, when the function is the image's own.
    pub reason: Option<String>,
}

/// A global the program defines: a datum the lift names, with the bytes
/// the image holds for it, zero where it holds none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Global {
    pub name: String,
    pub address: u64,
    pub bytes: Vec<u8>,
}

/// The pieces of a program.
#[derive(Clone, Default)]
pub struct Program<'a> {
    /// The functions, in the order they are written; each is declared
    /// before any is defined.
    pub functions: Vec<&'a Stages>,
    pub externals: Vec<External>,
    pub globals: Vec<Global>,
    /// The function `main` calls with the numbers on the command line,
    /// printing what it returns.
    pub harness: Option<&'a Stages>,
}

/// The names the C library declares in the headers the program includes,
/// which are not declared again.
const LIBRARY: &[&str] = &[
    "printf", "puts", "putchar", "fprintf", "sprintf", "snprintf", "scanf", "sscanf", "getchar",
    "fgets", "fputs", "fopen", "fclose", "fread", "fwrite", "fflush", "malloc", "calloc",
    "realloc", "free", "exit", "abort", "atoi", "atol", "strtol", "strtoll", "strtoul", "rand",
    "srand", "qsort", "memset", "memcpy", "memmove", "memcmp", "strlen", "strcmp", "strncmp",
    "strcpy", "strncpy", "strcat", "strchr", "strstr", "strdup", "abs", "labs", "getenv", "system",
    "time",
];

/// The program as C++.
pub fn program(program: &Program) -> String {
    let mut out = String::new();
    out.push_str(
        "// Lifted by AdmiralGrace: the medium level of each function, a label per block.\n",
    );
    out.push_str(
        "#include <cstdint>\n#include <cstdio>\n#include <cstdlib>\n#include <cstring>\n\n",
    );
    out.push_str("// A compare or test kept as a statement does nothing by itself.\n");
    out.push_str("template <class A, class B> static inline void __cmp(A, B) {}\n");
    out.push_str("template <class A, class B> static inline void __test(A, B) {}\n\n");
    if !program.globals.is_empty() {
        out.push_str("// The data the functions name, as the image holds it.\n");
        for global in &program.globals {
            out.push_str(&global_definition(global));
        }
        out.push('\n');
    }
    let defined: BTreeSet<&str> = program
        .functions
        .iter()
        .map(|stages| stages.function.name.as_str())
        .collect();
    let mut declared = false;
    for external in &program.externals {
        if defined.contains(external.name.as_str()) || LIBRARY.contains(&external.name.as_str()) {
            continue;
        }
        if !declared {
            out.push_str("// Functions the program calls and does not define.\n");
            declared = true;
        }
        if let Some(reason) = &external.reason {
            out.push_str(&format!("// {}: {reason}\n", external.name));
        }
        out.push_str(&format!(
            "extern \"C\" long {}(...);\n",
            identifier(&external.name)
        ));
    }
    if declared {
        out.push('\n');
    }
    if program.functions.len() > 1 {
        for stages in &program.functions {
            out.push_str(&signature(stages));
            out.push_str(";\n");
        }
        out.push('\n');
    }
    for stages in &program.functions {
        out.push_str(&function(stages));
        out.push('\n');
    }
    if let Some(stages) = program.harness {
        out.push_str(&harness(stages));
    }
    out
}

/// One function as C++: its signature, its locals, then each block of its
/// medium level under its label, ending in the `goto`s of its terminator.
pub fn function(stages: &Stages) -> String {
    let mut out = signature(stages);
    out.push_str("\n{\n");
    for local in &stages.function.locals {
        out.push_str(&format!("  {} {};\n", local.ty, identifier(&local.name)));
    }
    if !stages.function.locals.is_empty() {
        out.push('\n');
    }
    if stages.medium.is_empty() {
        // A thunk, or a lift without a medium level: the body is a call on.
        match &stages.function.thunk {
            Some(callee) => out.push_str(&format!(
                "  // thunk for {callee}\n  return {};\n",
                call_on(stages, callee)
            )),
            None => out.push_str("  abort(); // no blocks at the medium level\n"),
        }
        out.push_str("}\n");
        return out;
    }
    for node in &stages.medium {
        out.push_str(&format!("block_{:x}:\n", node.address));
        let mut returned = false;
        for statement in &node.statements {
            let text = crate::emit::emit_node(&statement.node)
                .trim_end()
                .trim_end_matches(';')
                .to_string();
            returned = matches!(statement.node, AstNode::Return { .. });
            out.push_str(&format!("  {text};\n"));
        }
        match &node.terminator {
            Terminator::Return => {
                if !returned {
                    if stages.function.return_type == "void" {
                        out.push_str("  return;\n");
                    } else {
                        out.push_str("  abort(); // returns without a value\n");
                    }
                }
            }
            Terminator::Goto { target, .. } => {
                out.push_str(&format!("  goto {};\n", label(stages, *target)));
            }
            Terminator::Branch {
                cond, taken, next, ..
            } => {
                let cond = crate::emit::emit_node(cond)
                    .trim_end()
                    .trim_end_matches(';')
                    .to_string();
                out.push_str(&format!(
                    "  if ({cond}) goto {}; else goto {};\n",
                    label(stages, *taken),
                    label(stages, *next)
                ));
            }
            Terminator::Switch { index, cases, .. } => {
                let index = crate::emit::emit_node(index)
                    .trim_end()
                    .trim_end_matches(';')
                    .to_string();
                out.push_str(&format!("  switch ({index}) {{\n"));
                for (values, target) in cases {
                    for value in values {
                        out.push_str(&format!("  case {value}:\n"));
                    }
                    out.push_str(&format!("    goto {};\n", label(stages, *target)));
                }
                out.push_str("  default:\n    abort(); // no case takes the value\n  }\n");
            }
        }
    }
    out.push_str("}\n");
    out
}

/// The function's signature: its return type, its name and its typed
/// parameters.
pub fn signature(stages: &Stages) -> String {
    let params = if stages.function.params.is_empty() {
        "void".to_string()
    } else {
        stages
            .function
            .params
            .iter()
            .map(|param| format!("{} {}", param.ty, identifier(&param.name)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "{} {}({params})",
        stages.function.return_type,
        identifier(&stages.function.name)
    )
}

/// A call of `callee` with this function's own parameters, for a thunk.
fn call_on(stages: &Stages, callee: &str) -> String {
    format!(
        "{}({})",
        identifier(callee),
        stages
            .function
            .params
            .iter()
            .map(|param| identifier(&param.name))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The label of block `target`, by its address.
fn label(stages: &Stages, target: usize) -> String {
    match stages.medium.get(target) {
        Some(node) => format!("block_{:x}", node.address),
        None => format!("block_{target}_missing"),
    }
}

/// A name as a C++ identifier: anything else becomes `_`, and a name
/// that starts with a digit or is a keyword gets a leading `_`.
pub fn identifier(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    const KEYWORDS: &[&str] = &[
        "auto", "bool", "break", "case", "char", "class", "const", "continue", "default", "delete",
        "do", "double", "else", "enum", "extern", "float", "for", "goto", "if", "int", "long",
        "new", "operator", "private", "public", "register", "return", "short", "signed", "sizeof",
        "static", "struct", "switch", "template", "this", "typedef", "union", "unsigned", "using",
        "virtual", "void", "volatile", "while", "main",
    ];
    if out.is_empty()
        || out.starts_with(|c: char| c.is_ascii_digit())
        || KEYWORDS.contains(&out.as_str())
    {
        out.insert(0, '_');
    }
    out
}

/// A global's definition: an integer of its width when it is one, else a
/// byte array, with the image's bytes.
fn global_definition(global: &Global) -> String {
    let name = identifier(&global.name);
    match global.bytes.len() {
        1 | 2 | 4 | 8 => {
            let mut word = [0u8; 8];
            word[..global.bytes.len()].copy_from_slice(&global.bytes);
            let value = u64::from_le_bytes(word);
            let ty = match global.bytes.len() {
                1 => "int8_t",
                2 => "int16_t",
                4 => "int32_t",
                _ => "int64_t",
            };
            format!(
                "static {ty} {name} = ({ty}){value:#x}; // at {:#x}\n",
                global.address
            )
        }
        0 => format!(
            "static int64_t {name} = 0; // at {:#x}, of a size the image does not say\n",
            global.address
        ),
        len => {
            let bytes: Vec<String> = global
                .bytes
                .iter()
                .map(|byte| format!("{byte:#04x}"))
                .collect();
            format!(
                "static unsigned char {name}[{len}] = {{{}}}; // at {:#x}\n",
                bytes.join(", "),
                global.address
            )
        }
    }
}

/// A `main` that calls the function with the numbers on its command line,
/// each parsed as `strtoll` reads it, and prints what it returns.
fn harness(stages: &Stages) -> String {
    let function = &stages.function;
    let mut out = String::new();
    out.push_str("int main(int argc, char **argv)\n{\n");
    let count = function.params.len();
    if count > 0 {
        out.push_str(&format!(
            "  long long args[{count}] = {{0}};\n  for (int i = 0; i < argc - 1 && i < {count}; i++) args[i] = strtoll(argv[i + 1], 0, 0);\n"
        ));
    }
    let args: Vec<String> = function
        .params
        .iter()
        .enumerate()
        .map(|(index, param)| format!("({})args[{index}]", param.ty))
        .collect();
    let call = format!("{}({})", identifier(&function.name), args.join(", "));
    if function.return_type == "void" {
        out.push_str(&format!("  {call};\n"));
    } else {
        out.push_str(&format!(
            "  {} result = {call};\n  printf(\"%lld\\n\", (long long)result);\n",
            function.return_type
        ));
    }
    out.push_str("  return 0;\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::BinaryOp;
    use crate::lift::{LiftedFunction, Statement, StatementKind, Variable};
    use crate::structure::{Analysis, Node};
    use std::collections::BTreeMap;

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

    fn stages() -> Stages {
        Stages {
            chains: Vec::new(),
            low: Vec::new(),
            medium: vec![
                Node {
                    address: 0x10,
                    statements: vec![statement(assign("total", AstNode::constant(0, 8)), 0x10)],
                    terminator: Terminator::Goto {
                        target: 1,
                        addresses: Vec::new(),
                    },
                },
                Node {
                    address: 0x20,
                    statements: Vec::new(),
                    terminator: Terminator::Branch {
                        cond: AstNode::binary(var("a"), BinaryOp::Greater, AstNode::constant(0, 4)),
                        taken: 2,
                        next: 3,
                        addresses: Vec::new(),
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
                                        target: Box::new(var("a")),
                                    },
                                ),
                            ),
                            0x30,
                        ),
                        statement(
                            assign(
                                "a",
                                AstNode::binary(var("a"), BinaryOp::Sub, AstNode::constant(1, 4)),
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
            ],
            high: Vec::new(),
            function: LiftedFunction {
                name: "sum".to_string(),
                address: 0x10,
                return_type: "long".to_string(),
                params: vec![Variable {
                    ty: "int".to_string(),
                    name: "a".to_string(),
                }],
                locals: vec![Variable {
                    ty: "long".to_string(),
                    name: "total".to_string(),
                }],
                body: Vec::new(),
                frame: Vec::new(),
                thunk: None,
                return_reason: None,
            },
            analysis: Analysis::default(),
            medium_analysis: Analysis::default(),
            stack_pointer: BTreeMap::new(),
            types: BTreeMap::new(),
        }
    }

    #[test]
    fn a_function_is_its_blocks_under_labels_with_gotos_between() {
        let text = function(&stages());
        assert_eq!(
            text,
            "long sum(int a)\n{\n  long total;\n\nblock_10:\n  total = 0;\n  goto block_20;\nblock_20:\n  if (a > 0) goto block_30; else goto block_40;\nblock_30:\n  total = total + (long)a;\n  a = a - 1;\n  goto block_20;\nblock_40:\n  return total;\n}\n"
        );
        let program = program(&Program {
            functions: vec![&stages()],
            externals: vec![
                External {
                    name: "printf".to_string(),
                    reason: None,
                },
                External {
                    name: "mystery".to_string(),
                    reason: Some("not lifted yet: the block ends in hlt".to_string()),
                },
            ],
            globals: vec![
                Global {
                    name: "counter".to_string(),
                    address: 0x4010,
                    bytes: vec![7, 0, 0, 0],
                },
                Global {
                    name: "table".to_string(),
                    address: 0x4020,
                    bytes: vec![1, 2, 3],
                },
            ],
            harness: Some(&stages()),
        });
        assert!(program.contains("#include <cstdint>"), "{program}");
        assert!(
            program.contains("static int32_t counter = (int32_t)0x7; // at 0x4010"),
            "{program}"
        );
        assert!(
            program.contains("static unsigned char table[3] = {0x01, 0x02, 0x03};"),
            "{program}"
        );
        assert!(program.contains("// mystery: not lifted yet: the block ends in hlt\nextern \"C\" long mystery(...);"), "{program}");
        assert!(
            !program.contains("long printf("),
            "the library declares printf: {program}"
        );
        assert!(
            program.contains("int main(int argc, char **argv)"),
            "{program}"
        );
        assert!(
            program.contains("long result = sum((int)args[0]);"),
            "{program}"
        );
        assert!(
            program.contains("printf(\"%lld\\n\", (long long)result);"),
            "{program}"
        );
        assert_eq!(identifier("completed.0"), "completed_0");
        assert_eq!(identifier("main"), "_main");
        assert_eq!(identifier("9lives"), "_9lives");
    }

    #[test]
    fn a_thunk_calls_on_and_a_switch_has_its_cases() {
        let mut thunk = stages();
        thunk.medium.clear();
        thunk.function.thunk = Some("puts".to_string());
        thunk.function.return_type = "void".to_string();
        let text = function(&thunk);
        assert!(
            text.contains("  // thunk for puts\n  return puts(a);\n"),
            "{text}"
        );
        let mut switched = stages();
        switched.medium[1].terminator = Terminator::Switch {
            index: AstNode::var("a"),
            cases: vec![(vec![1, 2], 2), (vec![3], 3)],
            addresses: Vec::new(),
        };
        let text = function(&switched);
        assert!(text.contains("  switch (a) {\n  case 1:\n  case 2:\n    goto block_30;\n  case 3:\n    goto block_40;\n  default:\n    abort();"), "{text}");
    }
}
