//! Lifted functions as C++ that compiles: the medium level — statements
//! over variables on the block graph — written out with a label per block
//! and a `goto` for every way out, the image's globals and imports
//! declared, and a `main` that calls one function with the arguments on
//! its command line, so a lifter's reading of the machine can be built
//! with a compiler and run beside the program it came from. The spelling
//! is the pseudocode's: the lift's own types and casts, which are C.
//!
//! A variable the analyst typed is declared with its type, the project's
//! definitions it needs written ahead of the functions; the medium level
//! reads it as the integer the machine held, so each read of it is cast to
//! the integer of its width and each value stored to it cast to its type.

use std::collections::BTreeSet;

use crate::ast::{AstNode, BinaryOp};
use crate::lift::Stages;
use crate::structure::Terminator;
use crate::types::{Type, TypeStore};

/// A function the program declares and does not define: an import, or a
/// function the lifter refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct External {
    pub name: String,
    /// Why there is no body, when the function is the image's own.
    pub reason: Option<String>,
    /// The function's own signature, when its lift is known and it is
    /// declared rather than defined.
    pub signature: Option<String>,
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
    /// The project's types, which the variables' types name; `None` for
    /// the platform's primitives alone.
    pub types: Option<&'a TypeStore>,
}

/// The functions the program declares exactly for its own use — the
/// harness's and the refusals' — and so does not declare again as calls.
const OWN: &[&str] = &["printf", "strtoll", "abort"];

/// The program as C++.
pub fn program(program: &Program) -> String {
    let mut out = String::new();
    out.push_str(
        "// Lifted by AdmiralGrace: the medium level of each function, a label per block.\n",
    );
    out.push_str("#include <cstdint>\n\n");
    out.push_str("// What the program itself calls, declared exactly; no header is included,\n");
    out.push_str("// so a function of the image may bear any name the C library has.\n");
    out.push_str("extern \"C\" int printf(const char *, ...);\n");
    out.push_str("extern \"C\" long long strtoll(const char *, char **, int);\n");
    out.push_str("extern \"C\" void abort(void);\n\n");
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
        if defined.contains(external.name.as_str()) || OWN.contains(&external.name.as_str()) {
            continue;
        }
        if !declared {
            out.push_str("// Functions the program calls and does not define.\n");
            declared = true;
        }
        if let Some(reason) = &external.reason {
            out.push_str(&format!("// {}: {reason}\n", external.name));
        }
        match &external.signature {
            Some(signature) => out.push_str(&format!("{signature};\n")),
            None => out.push_str(&format!(
                "extern \"C\" long {}(...);\n",
                identifier(&external.name)
            )),
        }
    }
    if declared {
        out.push('\n');
    }
    let platform = TypeStore::default();
    let store = program.types.unwrap_or(&platform);
    let definitions = definitions(&program.functions, store);
    if !definitions.is_empty() {
        out.push_str("// The types the functions' variables are declared with.\n");
        out.push_str(&definitions);
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
        out.push_str(&function_with(stages, store));
        out.push('\n');
    }
    if let Some(stages) = program.harness {
        out.push_str(&harness(stages));
    }
    out
}

/// The definitions of the project's types the functions' variables and
/// returns name, in an order C reads them in, as C.
fn definitions(functions: &[&Stages], store: &TypeStore) -> String {
    let types: Vec<Type> = functions
        .iter()
        .flat_map(|stages| {
            let function = &stages.function;
            function
                .params
                .iter()
                .chain(&function.locals)
                .map(|v| v.ty.as_str())
                .chain([function.return_type.as_str()])
        })
        .filter_map(|ty| crate::ctype::parse_type(store, ty).ok())
        .collect();
    let mut out = String::new();
    for key in store.needed_by(&types) {
        if store.is_anonymous(&key) {
            continue;
        }
        if let Some(text) = store.definition_text(&key, false) {
            out.push_str(&text);
            out.push('\n');
        }
    }
    out
}

/// The variables of a function the analyst typed, as the medium level
/// reads them: each with the integer of its width.
fn retyped(
    stages: &Stages,
    store: &TypeStore,
) -> std::collections::BTreeMap<String, (String, String)> {
    let mut out = std::collections::BTreeMap::new();
    for variable in stages.function.params.iter().chain(&stages.function.locals) {
        let Ok(ty) = crate::ctype::parse_type(store, &variable.ty) else {
            continue;
        };
        if matches!(store.resolve(&ty), Type::Prim(p) if p.is_integer()) || !store.is_scalar(&ty) {
            continue;
        }
        let Ok(size) = store.size_of(&ty) else {
            continue;
        };
        let integer = crate::lift::type_name(u32::try_from(size * 8).unwrap_or(64));
        out.insert(
            identifier(&variable.name),
            (integer.to_string(), ty.spelled(store)),
        );
    }
    out
}

/// `node` with each read of a typed variable cast to its integer, and each
/// value stored to one cast to its type.
fn cast_retyped(
    node: &AstNode,
    retyped: &std::collections::BTreeMap<String, (String, String)>,
) -> AstNode {
    if retyped.is_empty() {
        return node.clone();
    }
    let read = |node: AstNode| {
        crate::inline::map(node, &mut |n| match n {
            AstNode::Var { name } => match retyped.get(&identifier(&name)) {
                Some((integer, _)) => AstNode::Cast {
                    ty: integer.clone(),
                    target: Box::new(AstNode::Var { name }),
                },
                None => AstNode::Var { name },
            },
            // `&a` takes the variable's own address.
            AstNode::AddressOf { target } => match *target {
                AstNode::Cast { target: inner, ty } if matches!(inner.as_ref(), AstNode::Var { name } if retyped.contains_key(&identifier(name))) =>
                {
                    let _ = ty;
                    AstNode::AddressOf { target: inner }
                }
                other => AstNode::AddressOf {
                    target: Box::new(other),
                },
            },
            other => other,
        })
    };
    match node {
        AstNode::Assign { lhs, rhs } => match lhs.as_ref() {
            AstNode::Var { name } if retyped.contains_key(&identifier(name)) => {
                let (_, ty) = &retyped[&identifier(name)];
                AstNode::Assign {
                    lhs: lhs.clone(),
                    rhs: Box::new(AstNode::Cast {
                        ty: ty.clone(),
                        target: Box::new(read((**rhs).clone())),
                    }),
                }
            }
            _ => AstNode::Assign {
                lhs: Box::new(read((**lhs).clone())),
                rhs: Box::new(read((**rhs).clone())),
            },
        },
        other => read(other.clone()),
    }
}

/// One function as C++: its signature, its locals, then each block of its
/// medium level under its label, ending in the `goto`s of its terminator.
pub fn function(stages: &Stages) -> String {
    function_with(stages, &TypeStore::default())
}

/// [`function`], the variables' types read against `store`.
pub fn function_with(stages: &Stages, store: &TypeStore) -> String {
    let retyped = retyped(stages, store);
    let mut out = signature(stages);
    out.push_str("\n{\n");
    for local in &stages.function.locals {
        out.push_str(&format!(
            "  {};\n",
            crate::types::declaration(
                &crate::ctype::parse_type(store, &local.ty)
                    .unwrap_or_else(|_| Type::Named(local.ty.clone())),
                &identifier(&local.name),
                store
            )
        ));
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
            returned = matches!(statement.node, AstNode::Return { .. });
            out.push_str(&format!(
                "  {};\n",
                statement_text(&cast_retyped(&statement.node, &retyped))
            ));
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
                let cond = text_of(&cast_retyped(cond, &retyped));
                out.push_str(&format!(
                    "  if ({cond}) goto {}; else goto {};\n",
                    label(stages, *taken),
                    label(stages, *next)
                ));
            }
            Terminator::Switch { index, cases, .. } => {
                let index = text_of(&cast_retyped(index, &retyped));
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

/// An expression as C a compiler reads, its names as identifiers.
fn text_of(node: &AstNode) -> String {
    crate::emit::emit_node_c(&renamed(node))
        .trim_end()
        .trim_end_matches(';')
        .to_string()
}

/// A statement as C a compiler reads. An assignment of a function, an
/// address or a string to an integer variable converts it, as the machine
/// did by holding it in a register.
fn statement_text(node: &AstNode) -> String {
    // A struct initializer is the stores it stands for: a compiler reads no
    // anonymous struct in a cast.
    if let AstNode::Assign { lhs, rhs } = node {
        if let (AstNode::Deref { target }, AstNode::StructInit { fields }) =
            (lhs.as_ref(), rhs.as_ref())
        {
            let base = match target.as_ref() {
                AstNode::Cast { target, .. } => target.as_ref(),
                other => other,
            };
            return fields
                .iter()
                .map(|field| {
                    let pointer = AstNode::binary(
                        AstNode::Cast {
                            ty: "char *".to_string(),
                            target: Box::new(base.clone()),
                        },
                        BinaryOp::Add,
                        AstNode::constant(field.offset, 8),
                    );
                    let store = AstNode::Assign {
                        lhs: Box::new(AstNode::Deref {
                            target: Box::new(AstNode::Cast {
                                ty: format!("{} *", field.ty),
                                target: Box::new(pointer),
                            }),
                        }),
                        rhs: Box::new(field.value.clone()),
                    };
                    statement_text(&store)
                })
                .collect::<Vec<_>>()
                .join(";\n  ");
        }
    }
    // Where the walk did not go on, the program traps: the code there is
    // not analyzed, and nothing stands in for it.
    if crate::lift::halted_target(node).is_some() {
        return "__builtin_trap()".to_string();
    }
    // A builtin's pointer arguments are the integers the machine held;
    // the compiler's builtin wants pointers.
    if let AstNode::Intrinsic { name, args } = node {
        let types: &[&str] = match name.as_str() {
            "__builtin_memcpy" => &["void *", "const void *", "unsigned long"],
            "__builtin_memset" => &["void *", "int", "unsigned long"],
            "__builtin_strcpy" => &["char *", "const char *"],
            _ => &[],
        };
        if !types.is_empty() {
            let args = args
                .iter()
                .zip(types.iter().chain(std::iter::repeat(&"")))
                .map(|(arg, ty)| {
                    if ty.is_empty() || matches!(arg, AstNode::StringLiteral { .. }) {
                        arg.clone()
                    } else {
                        AstNode::Cast {
                            ty: ty.to_string(),
                            target: Box::new(arg.clone()),
                        }
                    }
                })
                .collect();
            return text_of(&AstNode::Intrinsic {
                name: name.clone(),
                args,
            });
        }
    }
    if let AstNode::Assign { lhs, rhs } = node {
        let converts = match rhs.as_ref() {
            AstNode::FunctionName { .. }
            | AstNode::AddressOf { .. }
            | AstNode::StringLiteral { .. } => true,
            AstNode::Cast { target, .. } => matches!(
                target.as_ref(),
                AstNode::FunctionName { .. }
                    | AstNode::AddressOf { .. }
                    | AstNode::StringLiteral { .. }
            ),
            _ => false,
        };
        if converts {
            let left = text_of(lhs);
            return format!("{left} = (decltype({left}))({})", text_of(rhs));
        }
    }
    text_of(node)
}

/// The expression with every variable and function name spelled as the
/// identifier the program declares it by.
fn renamed(node: &AstNode) -> AstNode {
    match node {
        AstNode::Var { name } => AstNode::var(identifier(name)),
        AstNode::FunctionName { name, address } => AstNode::FunctionName {
            name: identifier(name),
            address: *address,
        },
        AstNode::Assign { lhs, rhs } => AstNode::Assign {
            lhs: Box::new(renamed(lhs)),
            rhs: Box::new(renamed(rhs)),
        },
        AstNode::Binary { lhs, op, rhs } => AstNode::Binary {
            lhs: Box::new(renamed(lhs)),
            op: *op,
            rhs: Box::new(renamed(rhs)),
        },
        AstNode::Deref { target } => AstNode::Deref {
            target: Box::new(renamed(target)),
        },
        AstNode::AddressOf { target } => AstNode::AddressOf {
            target: Box::new(renamed(target)),
        },
        AstNode::Cast { ty, target } => AstNode::Cast {
            ty: ty.clone(),
            target: Box::new(renamed(target)),
        },
        // A call through an expression goes through a pointer to a function
        // of integers, and a function passed as an argument is the integer
        // the machine held — a compiler reads neither bare.
        AstNode::Call { callee, args } => AstNode::Call {
            callee: Box::new(match callee.as_ref() {
                AstNode::FunctionName { .. } => renamed(callee),
                through => AstNode::Cast {
                    ty: "long (*)(...)".to_string(),
                    target: Box::new(renamed(through)),
                },
            }),
            args: args
                .iter()
                .map(|arg| match arg {
                    AstNode::FunctionName { .. } => AstNode::Cast {
                        ty: "long".to_string(),
                        target: Box::new(renamed(arg)),
                    },
                    other => renamed(other),
                })
                .collect(),
        },
        AstNode::Intrinsic { name, args } => AstNode::Intrinsic {
            name: name.clone(),
            args: args.iter().map(renamed).collect(),
        },
        AstNode::StructInit { fields } => AstNode::StructInit {
            fields: fields
                .iter()
                .map(|field| crate::ast::StructField {
                    ty: field.ty.clone(),
                    offset: field.offset,
                    value: renamed(&field.value),
                })
                .collect(),
        },
        AstNode::Return { value } => AstNode::Return {
            value: value.as_ref().map(|value| Box::new(renamed(value))),
        },
        AstNode::Ternary {
            cond,
            then,
            otherwise,
        } => AstNode::Ternary {
            cond: Box::new(renamed(cond)),
            then: Box::new(renamed(then)),
            otherwise: Box::new(renamed(otherwise)),
        },
        AstNode::ConstantCondition { holds, compared } => AstNode::ConstantCondition {
            holds: *holds,
            compared: Box::new(renamed(compared)),
        },
        other => other.clone(),
    }
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
            .map(|param| crate::stack_vars::declarator(&param.ty, &identifier(&param.name)))
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
        "alignas",
        "alignof",
        "and",
        "and_eq",
        "asm",
        "auto",
        "bitand",
        "bitor",
        "bool",
        "break",
        "case",
        "catch",
        "char",
        "char8_t",
        "char16_t",
        "char32_t",
        "class",
        "compl",
        "concept",
        "const",
        "consteval",
        "constexpr",
        "constinit",
        "const_cast",
        "continue",
        "co_await",
        "co_return",
        "co_yield",
        "decltype",
        "default",
        "delete",
        "do",
        "double",
        "dynamic_cast",
        "else",
        "enum",
        "explicit",
        "export",
        "extern",
        "false",
        "float",
        "for",
        "friend",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "mutable",
        "namespace",
        "new",
        "noexcept",
        "not",
        "not_eq",
        "nullptr",
        "operator",
        "or",
        "or_eq",
        "private",
        "protected",
        "public",
        "register",
        "reinterpret_cast",
        "requires",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "static_assert",
        "static_cast",
        "struct",
        "switch",
        "template",
        "this",
        "thread_local",
        "throw",
        "true",
        "try",
        "typedef",
        "typeid",
        "typename",
        "union",
        "unsigned",
        "using",
        "virtual",
        "void",
        "volatile",
        "wchar_t",
        "while",
        "xor",
        "xor_eq",
        "main",
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
                    placements: Vec::new(),
                    fragment: None,
                }],
                locals: vec![Variable {
                    ty: "long".to_string(),
                    name: "total".to_string(),
                    placements: Vec::new(),
                    fragment: None,
                }],
                body: Vec::new(),
                frame: Vec::new(),
                thunk: None,
                notes: Vec::new(),
                call_notes: Vec::new(),
                noreturn_when: Vec::new(),
                return_reason: None,
            },
            analysis: Analysis::default(),
            medium_analysis: Analysis::default(),
            stack_pointer: BTreeMap::new(),
            types: BTreeMap::new(),
            slots: Default::default(),
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
                    signature: None,
                },
                External {
                    name: "mystery".to_string(),
                    reason: Some("not lifted yet: the block ends in hlt".to_string()),
                    signature: None,
                },
                External {
                    name: "helper".to_string(),
                    reason: None,
                    signature: Some("int helper(int a)".to_string()),
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
            types: None,
        });
        assert!(program.contains("#include <cstdint>"), "{program}");
        assert!(
            !program.contains("#include <cstdio>"),
            "no header: {program}"
        );
        assert!(
            program.contains("extern \"C\" int printf(const char *, ...);"),
            "{program}"
        );
        assert!(program.contains("int helper(int a);"), "{program}");
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
        assert_eq!(identifier("this"), "_this");
        // A use is spelled as its declaration is, and a function held as a
        // value converts to the integer it is held in.
        let global = AstNode::Assign {
            lhs: Box::new(AstNode::var("rax")),
            rhs: Box::new(AstNode::AddressOf {
                target: Box::new(AstNode::var("completed.0")),
            }),
        };
        assert_eq!(
            statement_text(&global),
            "rax = (decltype(rax))(&completed_0)"
        );
        let function = AstNode::Assign {
            lhs: Box::new(AstNode::var("rax")),
            rhs: Box::new(AstNode::FunctionName {
                name: "main".to_string(),
                address: 0x1198,
            }),
        };
        assert_eq!(statement_text(&function), "rax = (decltype(rax))(_main)");
        let test = AstNode::binary(
            AstNode::var("completed.0"),
            BinaryOp::NotEqual,
            AstNode::constant(0, 1),
        );
        assert_eq!(text_of(&test), "completed_0 != 0");
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

    #[test]
    fn a_builtins_pointer_arguments_are_cast_for_the_compiler() {
        let call = |name: &str, args: Vec<AstNode>| AstNode::Intrinsic {
            name: name.to_string(),
            args,
        };
        assert_eq!(
            statement_text(&call(
                "__builtin_memcpy",
                vec![AstNode::var("a"), AstNode::var("b"), AstNode::var("c")]
            )),
            "__builtin_memcpy((void *)a, (const void *)b, (unsigned long)c)"
        );
        assert_eq!(
            statement_text(&call(
                "__builtin_strcpy",
                vec![
                    AstNode::AddressOf {
                        target: Box::new(AstNode::var("local_d")),
                    },
                    AstNode::StringLiteral {
                        text: "hi".to_string(),
                    },
                ]
            )),
            "__builtin_strcpy((char *)&local_d, \"hi\")"
        );
        assert_eq!(
            statement_text(&call("__cmp", vec![AstNode::var("a"), AstNode::var("b")])),
            "__cmp(a, b)"
        );
    }

    #[test]
    fn a_call_through_an_expression_and_a_function_passed_are_cast_for_the_compiler() {
        let through = AstNode::Call {
            callee: Box::new(AstNode::var("a")),
            args: vec![AstNode::var("b"), AstNode::constant(1, 4)],
        };
        assert_eq!(statement_text(&through), "((long (*)(...))a)(b, 1)");
        let passed = AstNode::Call {
            callee: Box::new(AstNode::FunctionName {
                name: "call_through".to_string(),
                address: 0x2000,
            }),
            args: vec![
                AstNode::FunctionName {
                    name: "add".to_string(),
                    address: 0x1000,
                },
                AstNode::constant(2, 4),
            ],
        };
        assert_eq!(statement_text(&passed), "call_through((long)add, 2)");
    }
}
