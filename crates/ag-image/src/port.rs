//! Carrying types and signatures across matched functions (#381, #398).
//!
//! A project is annotations keyed by address, so two builds of a binary
//! hold their analyst's types at different addresses. This module carries
//! the types of a source project — its definitions, and the variable
//! types of its functions — onto a destination: the functions are already
//! matched, by whatever evidence drew the pairs — a symbol both images
//! name (`ag project types port`), or a whole-function hash, a name or a
//! shape (`ag diff`, the workbench's comparison) — and every source
//! definition the ported types name comes with it.
//!
//! The carry is `carry` (what would move, and what is held back) and
//! `apply` (the move), the way the header import is. A definition the
//! destination already holds with the same C text is held once, not
//! twice; one it holds differently is held back by name, so no port
//! changes the shape of a type already held. A signature is held back
//! when its type does not read, when it names a definition no store
//! defines, or when the variable is already typed differently in the
//! destination. A stack variable the destination already holds at the
//! same offset stands.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctype::{build, parse_into, parse_type, TypeText};
use crate::{DataModel, Type, TypeStore};

/// One variable's type on a function's record, as the source project
/// holds it: the lift name of the variable, and the type, `struct point *`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureWord {
    /// The variable's lift name.
    pub variable: String,
    /// The C type: `struct point *`, `enum state`, `uint32_t`.
    pub ty: String,
}

/// One stack variable the source project made in a function's frame:
/// its place and how it is declared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StackWord {
    /// Offset from the stack pointer at the function's entry, `-32` for
    /// the bytes `local_20` starts at.
    pub offset: i64,
    /// The size in bytes.
    pub size: u32,
    /// The name, which is the variable's lift name; the lift's `local_<hex>`
    /// when absent.
    pub name: Option<String>,
    /// The C type: `int`, `char *`, `char[16]`; one of the size when absent.
    pub ty: Option<String>,
}

/// The part of one function's record that a port carries: the types of
/// its variables, and the stack variables it made.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionRecord {
    /// The function's entry address in the source project, in its
    /// canonical spelling.
    pub address: String,
    /// The types given its variables, one per variable.
    pub var_types: Vec<SignatureWord>,
    /// The stack variables it made, in the order they were made.
    pub stack_vars: Vec<StackWord>,
}

/// The part of a project a port reads: every definition, and the
/// function records of the ones any type is held on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceProject {
    /// The definitions of the source, in the order its C reads.
    pub definitions: Vec<TypeText>,
    /// Every function record that carries a type or a stack variable.
    pub functions: Vec<FunctionRecord>,
}

/// One matched pair of functions, and what moves between them: the
/// source's entry, the destination's, the symbol they matched on, and
/// the types and stack variables that move with them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchedFunction {
    /// The symbol name the two functions matched on.
    pub symbol: String,
    /// The source's entry address, in its canonical spelling.
    pub source: String,
    /// The destination's entry address, in its canonical spelling.
    pub dest: String,
    /// The variable types of the source, in the order they stand.
    pub var_types: Vec<SignatureWord>,
    /// The stack variables the source made, in the order they stand.
    pub stack_vars: Vec<StackWord>,
}

/// A type definition the port holds back, with why: the name it could
/// not add, and the reason.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeldType {
    /// The definition's name: `struct point`, `node_t`.
    pub name: String,
    /// Why it is held back: the parse error, the differing definition
    /// already held, or the name it needs that the port does not bring.
    pub reason: String,
}

/// A signature the port holds back, with why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeldSignature {
    /// The function, by the symbol it matched on: `init`.
    pub function: String,
    /// The variable, `a`.
    pub variable: String,
    /// Why it is held back: the parse error, the type it names that
    /// neither side defines, the different type already given, or the
    /// absent variable.
    pub reason: String,
}

/// A source function the port did not match, with why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnmatchedFunction {
    /// The source's entry address, in its canonical spelling.
    pub source: String,
    /// Why no match was drawn: the source's spellings name no function in
    /// the destination image, or only one ambiguously.
    pub reason: String,
}

/// What a port holds: the definitions added, the matched functions
/// whose signatures move, the source functions unmatched, and what is
/// held back with its why.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PortPreview {
    /// The definitions the port adds, in the order they stand.
    pub definitions: Vec<TypeText>,
    /// The matched function pairs the port carries signatures to, in
    /// the order the source holds them.
    pub functions: Vec<MatchedFunction>,
    /// The source functions the port did not match, each with why.
    pub unmatched: Vec<UnmatchedFunction>,
    /// The definitions held back, each with why.
    pub held_types: Vec<HeldType>,
    /// The signatures held back, each with why.
    pub held_signatures: Vec<HeldSignature>,
    /// The names the port adds, in the order they stand.
    pub added: Vec<String>,
    /// The variable words the port applies, in the order they stand:
    /// each a function's destination address and the word to put on it.
    pub applied: Vec<(String, SignatureWord)>,
    /// The stack words the port applies, in the order they stand: each
    /// a function's destination address and the word to put on it.
    pub applied_stack: Vec<(String, StackWord)>,
    /// The notes the port leaves on the way through.
    pub notes: Vec<String>,
}

/// The word for one variable of `function` a port applies: its
/// destination address, the word, and the symbol of the function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppliedWord {
    /// The destination's entry address, in its canonical spelling.
    pub address: String,
    /// The symbol the two functions matched on.
    pub symbol: String,
    /// The variable's lift name.
    pub variable: String,
    /// The C type, as the port checked it.
    pub ty: String,
}

/// The word for one stack variable of `function` a port applies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppliedStack {
    /// The destination's entry address, in its canonical spelling.
    pub address: String,
    /// The symbol the two functions matched on.
    pub symbol: String,
    /// The stack variable, as the source made it.
    pub word: StackWord,
}

/// What `apply` gives: the destination's definitions after the port,
/// the words it applies, and what was held back with its why.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PortResult {
    /// The destination's definitions, in the order C reads them.
    pub definitions: Vec<TypeText>,
    /// The names added, in the order they stand.
    pub added: Vec<String>,
    /// The variable words applied, in the order they stand.
    pub applied: Vec<AppliedWord>,
    /// The stack words applied, in the order they stand.
    pub applied_stack: Vec<AppliedStack>,
    /// The matched pairs the port carried signatures to.
    pub functions: Vec<MatchedFunction>,
    /// The source functions unmatched, each with why.
    pub unmatched: Vec<UnmatchedFunction>,
    /// The definitions held back, each with why.
    pub held_types: Vec<HeldType>,
    /// The signatures held back, each with why.
    pub held_signatures: Vec<HeldSignature>,
    /// The notes the port leaves on the way through.
    pub notes: Vec<String>,
}

/// The held side of a destination a port reads: its definitions, its
/// signatures by function address, and the variables each destination
/// function declares.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HeldProject {
    /// The destination's definitions, in the order its C reads.
    pub definitions: Vec<TypeText>,
    /// The destination's signatures, by the destination's canonical
    /// address of each function's record.
    pub signatures: BTreeMap<String, Vec<SignatureWord>>,
    /// The destination's stack variables, by the destination's canonical
    /// address of each function's record.
    pub stack_vars: BTreeMap<String, Vec<StackWord>>,
    /// The variables the destination's function declares, by the
    /// destination's canonical address of each function's record; a
    /// port holds back a signature for one it does not.
    pub declared: BTreeMap<String, BTreeSet<String>>,
}

/// The names `ty` names that `store` does not define.
fn missing_names(store: &TypeStore, ty: &Type) -> Vec<String> {
    let mut names = BTreeSet::new();
    ty.names(&mut names);
    names
        .into_iter()
        .filter(|name| store.get(name).is_none())
        .collect()
}

/// The keys of `store`'s named definitions, in the order defined.
fn store_names(store: &TypeStore) -> Vec<String> {
    store
        .names()
        .iter()
        .map(|name| (*name).to_string())
        .collect()
}

/// Whether `name` is a type name that needs no definition of its own:
/// one the source store does not define either, such as a primitive
/// typedef the platform gives without a definition.
fn is_platform(name: &str) -> bool {
    // A spelling `Prim::named` reads, or a name `ctype` knows for the
    // platform. One of the primitives' own spellings, or a fixed-width
    // one the platform's headers give: neither is a definition a port
    // brings.
    if crate::Prim::named(name).is_some() {
        return true;
    }
    matches!(
        name,
        "int8_t"
            | "uint8_t"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
            | "int64_t"
            | "uint64_t"
            | "wchar_t"
            | "size_t"
            | "ssize_t"
            | "intptr_t"
            | "uintptr_t"
            | "ptrdiff_t"
            | "intmax_t"
            | "uintmax_t"
            | "int_fast8_t"
            | "uint_fast8_t"
            | "int_fast16_t"
            | "uint_fast16_t"
            | "int_fast32_t"
            | "uint_fast32_t"
            | "int_fast64_t"
            | "uint_fast64_t"
            | "int_least8_t"
            | "uint_least8_t"
            | "int_least16_t"
            | "uint_least16_t"
            | "int_least32_t"
            | "uint_least32_t"
            | "int_least64_t"
            | "uint_least64_t"
            | "bool"
            | "_Bool"
    )
}

/// The one `parse_into` reads of a definition against `store`.
fn parse_definition(
    store: &mut TypeStore,
    text: &TypeText,
) -> Result<crate::ctype::Parsed, String> {
    parse_into(store, &text.c).map_err(|error| error.to_string())
}

/// The plan of a port of `source` into a destination that holds `held`,
/// over functions already matched.
///
/// Every definition the matched signatures name, with what those name in
/// turn, is drawn from `source`, so a signature is carried whole or held
/// back whole. A definition held back does not stop the rest of the port;
/// its users are held back with it. The `unmatched` of the preview is left
/// empty: the caller that drew the matches names what it did not match.
pub fn carry(
    matched: &[MatchedFunction],
    source: &SourceProject,
    held: &HeldProject,
) -> Result<PortPreview, String> {
    let model = DataModel::LP64;
    // A destination store that does not read refuses a port's plan:
    // the first that does not read is held back by its name, so its
    // absence stands in the report.
    let (dest_store, _) = build(model, &held.definitions)?;

    // Draw every definition the matched signatures name, reading each
    // variable type against the source store: the abstract shapes it
    // names are its keywords, and the ones the signatures actually need
    // are drawn whole or not at all.
    let (source_store, _) = build(model, &source.definitions)?;
    let mut drawn_types: Vec<Type> = Vec::new();
    let mut type_parse_errors: Vec<(String, String, String)> = Vec::new();
    for fun in matched {
        for word in &fun.var_types {
            match parse_type(&source_store, &word.ty) {
                Ok(ty) => drawn_types.push(ty),
                Err(error) => type_parse_errors.push((
                    fun.symbol.clone(),
                    word.variable.clone(),
                    error.to_string(),
                )),
            }
        }
        for word in &fun.stack_vars {
            if let Some(text) = word.ty.as_deref() {
                let fallback = word.spelled_as_source();
                let named = word.name.as_deref().unwrap_or(&fallback);
                match parse_type(&source_store, text) {
                    Ok(ty) => drawn_types.push(ty),
                    Err(error) => type_parse_errors.push((
                        fun.symbol.clone(),
                        named.to_string(),
                        error.to_string(),
                    )),
                }
            }
        }
    }
    let needed = source_store.needed_by(&drawn_types);
    let needed_set: BTreeSet<String> = needed.iter().cloned().collect();
    // The names the drawn types name, for a signature's missing-name
    // check: one of these the source defines, or a primitive spelling,
    // is defined somewhere; any other name is not.
    let mut named_in_source: BTreeSet<String> = BTreeSet::new();
    for definition in &source.definitions {
        if needed_set.contains(&definition.name) {
            for name in source_definitions_of(definition, &source_store) {
                named_in_source.insert(name);
            }
        }
    }
    for name in store_names(&source_store) {
        if needed_set.contains(&name) {
            named_in_source.insert(name.clone());
        }
    }

    // Walk the source's definitions in source order, admitting one whose
    // every named type is held already, drawn already, or a platform
    // name. A source definition the destination defines differently is
    // held back by name, so no port changes the shape of a type already
    // held; one already drawn is drawn once only. A definition already
    // held with the same C text is held once, not twice, and is not
    // drawn at all.
    let held_by_name: BTreeMap<&str, &TypeText> = held
        .definitions
        .iter()
        .map(|definition| (definition.name.as_str(), definition))
        .collect();
    let mut accepted: Vec<TypeText> = Vec::new();
    let mut held_types: Vec<HeldType> = Vec::new();
    let mut added: Vec<String> = Vec::new();
    let mut blocked: BTreeMap<String, String> = BTreeMap::new();
    let mut growing = dest_store.clone();
    let mut definitions_final: Vec<TypeText> = held.definitions.clone();

    for definition in &source.definitions {
        // Only what the matched signatures need is drawn.
        let defined = source_definitions_of(definition, &source_store);
        let needed_here = defined.iter().any(|name| needed_set.contains(name))
            || needed_set.contains(&definition.name);
        if !needed_here {
            continue;
        }
        if accepted
            .iter()
            .any(|held_def| held_def.name == definition.name)
        {
            continue;
        }
        // The definition's own names, for a later duplicate: a name
        // already drawn by an accepted definition is not drawn again.
        if let Some(held_def) = held_by_name.get(definition.name.as_str()) {
            if held_def.c == definition.c {
                // Held already with the same C: held once, not twice.
                continue;
            }
            held_types.push(HeldType {
                name: definition.name.clone(),
                reason: format!("{} is defined already", definition.name),
            });
            blocked.insert(
                definition.name.clone(),
                format!("{} is defined already", definition.name),
            );
            // A name of this definition drawn twice is the same refusal
            // as a name held differently: one shape only.
            for name in &defined {
                blocked.insert(
                    name.clone(),
                    format!("{} is defined already", definition.name),
                );
            }
            continue;
        }
        // A name of this definition drawn earlier is the same refusal:
        // a name the destination already defines differently is held
        // back by name, so no port changes the shape of a type already
        // held.
        if let Some(holder) = defined
            .iter()
            .find_map(|name| accepted.iter().find(|a| a.name == *name))
        {
            held_types.push(HeldType {
                name: definition.name.clone(),
                reason: format!("{} is defined already", definition.name),
            });
            blocked.insert(
                definition.name.clone(),
                format!("{} is defined already", definition.name),
            );
            let _ = holder;
            continue;
        }
        // Parse against the growing destination store: a definition
        // that reads is drawn, in source order; one that does not is
        // held back with its reason, and what needs it is held back
        // too.
        let mut probe = growing.clone();
        match parse_definition(&mut probe, definition) {
            Ok(parsed) => {
                // Names drawn from the declaration first: a name only
                // declared, not defined, does not count as drawn.
                for declared in &parsed.declarations {
                    let is_defined =
                        probe.get(&declared.name).is_some() || defined.contains(&declared.name);
                    if is_defined && !accepted.iter().any(|a| a.name == declared.name) {
                        if let Some(def) = definitions_final
                            .iter()
                            .find(|d: &&TypeText| d.name == declared.name)
                        {
                            let _ = def;
                            continue;
                        }
                        if !added.contains(&declared.name) {
                            added.push(declared.name.clone());
                        }
                    }
                }
                growing = probe;
                accepted.push(definition.clone());
            }
            Err(error) => {
                held_types.push(HeldType {
                    name: definition.name.clone(),
                    reason: error,
                });
                blocked.insert(definition.name.clone(), "was held back".to_string());
            }
        }
    }
    for definition in &accepted {
        definitions_final.push(definition.clone());
    }
    let (final_store, _) = build(model, &definitions_final)?;

    // Check each matched signature against the final store: a name the
    // final store defines is one this port brings. A name none defines
    // is held back: the port has no way to know its shape.
    let mut applied: Vec<(String, SignatureWord)> = Vec::new();
    let mut applied_stack: Vec<(String, StackWord)> = Vec::new();
    let mut held_signatures: Vec<HeldSignature> = Vec::new();
    let mut type_errors: BTreeMap<(String, String), String> = BTreeMap::new();
    for (function, variable, error) in type_parse_errors {
        type_errors.insert((function, variable), error);
    }

    for fun in matched {
        // Check each variable word of the matched function.
        for word in &fun.var_types {
            let key = (fun.symbol.clone(), word.variable.clone());
            if let Some(error) = type_errors.remove(&key) {
                held_signatures.push(HeldSignature {
                    function: fun.symbol.clone(),
                    variable: word.variable.clone(),
                    reason: error,
                });
                continue;
            }
            match held.declared.get(&fun.dest) {
                Some(declared) if !declared.contains(&word.variable) => {
                    held_signatures.push(HeldSignature {
                        function: fun.symbol.clone(),
                        variable: word.variable.clone(),
                        reason: format!("{} declares no {}", fun.symbol, word.variable),
                    });
                    continue;
                }
                None => {
                    held_signatures.push(HeldSignature {
                        function: fun.symbol.clone(),
                        variable: word.variable.clone(),
                        reason: format!(
                            "{} declares no {}",
                            fun.symbol, word.variable
                        ),
                    });
                    continue;
                }
                Some(_) => {}
            }
            let Some(ty) = parse_type(&final_store, &word.ty).ok() else {
                held_signatures.push(HeldSignature {
                    function: fun.symbol.clone(),
                    variable: word.variable.clone(),
                    reason: format!("{} does not read", word.ty),
                });
                continue;
            };
            let missing = missing_names(&final_store, &ty);
            if !missing.is_empty() {
                let name = missing[0].clone();
                held_signatures.push(HeldSignature {
                    function: fun.symbol.clone(),
                    variable: word.variable.clone(),
                    reason: format!("{name} is not defined"),
                });
                continue;
            }
            // A name the source store does not define either is not one
            // this port brings: a name held back in the walk, or one the
            // source never defines. Its user's signature is held back
            // with it.
            if let Some(name) = ty_named_outside(&ty, &final_store, &named_in_source) {
                held_signatures.push(HeldSignature {
                    function: fun.symbol.clone(),
                    variable: word.variable.clone(),
                    reason: format!("{name} is not defined"),
                });
                continue;
            }
            let spelled = ty.spelled(&final_store);
            // The same word already held stands; one held differently
            // is held back, so a port never retypes a variable.
            if let Some(held_start) = held
                .signatures
                .get(&fun.dest)
                .and_then(|held_here| held_here.iter().find(|w| w.variable == word.variable))
            {
                if held_start.ty == spelled {
                    continue;
                }
                held_signatures.push(HeldSignature {
                    function: fun.symbol.clone(),
                    variable: word.variable.clone(),
                    reason: format!("{} is already typed {}", word.variable, held_start.ty),
                });
                continue;
            }
            applied.push((
                fun.dest.clone(),
                SignatureWord {
                    variable: word.variable.clone(),
                    ty: spelled,
                },
            ));
        }

        // Check each stack word of the matched function.
        for word in &fun.stack_vars {
            let label = word
                .name
                .clone()
                .unwrap_or_else(|| word.spelled_as_source());
            let key = (fun.symbol.clone(), label.clone());
            if let Some(error) = type_errors.remove(&key) {
                held_signatures.push(HeldSignature {
                    function: fun.symbol.clone(),
                    variable: label,
                    reason: error,
                });
                continue;
            }
            if let Some(text) = word.ty.as_deref() {
                let Some(ty) = parse_type(&final_store, text).ok() else {
                    held_signatures.push(HeldSignature {
                        function: fun.symbol.clone(),
                        variable: label,
                        reason: format!("{text} does not read"),
                    });
                    continue;
                };
                let missing = missing_names(&final_store, &ty);
                if !missing.is_empty() {
                    held_signatures.push(HeldSignature {
                        function: fun.symbol.clone(),
                        variable: label,
                        reason: format!("{} is not defined", missing[0]),
                    });
                    continue;
                }
                if let Some(name) = ty_named_outside(&ty, &final_store, &named_in_source) {
                    held_signatures.push(HeldSignature {
                        function: fun.symbol.clone(),
                        variable: label,
                        reason: format!("{name} is not defined"),
                    });
                    continue;
                }
            }
            // A variable the destination already holds at the same
            // offset stands; the port does not re-make it.
            let already = held.stack_vars.get(&fun.dest).and_then(|held_here| {
                held_here
                    .iter()
                    .find(|w: &&StackWord| w.offset == word.offset)
            });
            if already.is_some() {
                continue;
            }
            applied_stack.push((fun.dest.clone(), word.clone()));
        }
    }

    Ok(PortPreview {
        definitions: definitions_final,
        functions: matched.to_vec(),
        unmatched: Vec::new(),
        held_types,
        held_signatures,
        added,
        applied,
        applied_stack,
        notes: Vec::new(),
    })
}

/// The names `definition` defines, read by parsing it alone and asking
/// the store it builds: every name it declares, that its C reads as a
/// definition.
fn source_definitions_of(definition: &TypeText, source_store: &TypeStore) -> Vec<String> {
    let mut fresh = TypeStore::new(*source_store.model());
    if parse_into(&mut fresh, &definition.c).is_err() {
        return vec![definition.name.clone()];
    }
    let mut names = store_names(&fresh);
    if names.is_empty() {
        names.push(definition.name.clone());
    }
    names
}

/// One name `ty` names that a store without drawn definitions does not
/// define yet: a name a definition does not draw either, or one held
/// back in the walk.
fn ty_named_outside(ty: &Type, store: &TypeStore, in_source: &BTreeSet<String>) -> Option<String> {
    // Names the store defines are drawn; names it does not are the
    // missing ones here. Names the source defines that the port did not
    // draw are held back's consequence: the definitions_final store
    // lacks them, so they are missing there.
    missing_names(store, ty)
        .into_iter()
        .find(|name| !in_source.contains(name) && !is_platform(name))
}

/// A stack variable's place as the source project spells it, for a
/// report or a refusal.
fn spelled_stack(word: &StackWord) -> String {
    let sign = if word.offset < 0 { '-' } else { '+' };
    let bytes = if word.size == 1 { "byte" } else { "bytes" };
    format!(
        "[sp{sign}{:#x}] {} {bytes}",
        word.offset.unsigned_abs(),
        word.size
    )
}

impl StackWord {
    /// The stack variable's place as the source project spells it.
    fn spelled_as_source(&self) -> String {
        spelled_stack(self)
    }
}

/// Carry the ported types and signatures of already-matched functions
/// into the destination that holds `held`, and say what moved and what
/// was held back.
pub fn apply(
    matched: &[MatchedFunction],
    source: &SourceProject,
    held: &HeldProject,
) -> Result<PortResult, String> {
    let plan = carry(matched, source, held)?;
    let applied = plan
        .applied
        .iter()
        .map(|pair| AppliedWord {
            address: pair.0.clone(),
            symbol: plan
                .functions
                .iter()
                .find(|f| f.dest == pair.0)
                .map(|f| f.symbol.clone())
                .unwrap_or_default(),
            variable: pair.1.variable.clone(),
            ty: pair.1.ty.clone(),
        })
        .collect();
    let applied_stack = plan
        .applied_stack
        .iter()
        .map(|pair| AppliedStack {
            address: pair.0.clone(),
            symbol: plan
                .functions
                .iter()
                .find(|f| f.dest == pair.0)
                .map(|f| f.symbol.clone())
                .unwrap_or_default(),
            word: pair.1.clone(),
        })
        .collect();
    Ok(PortResult {
        definitions: plan.definitions.clone(),
        added: plan.added.clone(),
        applied,
        applied_stack,
        functions: plan.functions.clone(),
        unmatched: plan.unmatched.clone(),
        held_types: plan.held_types.clone(),
        held_signatures: plan.held_signatures.clone(),
        notes: plan.notes.clone(),
    })
}
