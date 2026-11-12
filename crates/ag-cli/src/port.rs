//! Port types and signatures from one project to another by matching
//! symbols (#381).
//!
//! A project is annotations keyed by address, so two builds of a binary
//! hold their analyst's types at different addresses. This module carries
//! the types of a source project — its definitions, and the variable
//! types of its functions — into a destination project: a function on
//! one side is found on the other by its symbol name, and every source
//! definition the ported types name comes with it.
//!
//! "Matching symbols" is this: a symbol both images name is the same
//! function — `init` of one build and `init` of the other. The source
//! side's spellings are the name its image prints, the mangled spelling
//! when that is what printed, and the analyst's own rename of the entry;
//! the destination is searched by those same three spellings, its image's
//! own names first and a rename last, since a rename recorded for one
//! version names that version's address and no other.
//!
//! The carry itself — what moves, what is held back and why — is the
//! engine-adjacent [`ag_image::port`], shared with the version comparison
//! (`ag diff --apply`, the workbench), which matches functions by hash,
//! name or shape instead of by symbol and carries the types the same way.

use std::collections::{BTreeMap, BTreeSet};

use ag_corpus::project::canonical_address;

pub use ag_image::port::{
    FunctionRecord, HeldProject, MatchedFunction, PortPreview, PortResult, SignatureWord,
    SourceProject, StackWord, UnmatchedFunction,
};

/// The image side of a symbol match: each function's entry and the
/// names that entry answers to.
#[derive(Debug, Clone)]
pub struct SymbolImage {
    /// Each function's entry, its image spelling, the mangled spelling
    /// when the image demangled one, and the analyst's name for it.
    pub functions: Vec<SymbolFunction>,
}

/// One function of a symbol image, as a port matches on: an entry
/// address, the names that address answers to on one side, and the
/// analyst's rename for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolFunction {
    /// The entry address.
    pub address: u64,
    /// The name the image prints: `init`, `geometry::area(int, int)`.
    pub name: String,
    /// The spelling the symbol table holds, when one was demangled:
    /// `_ZN8geometry4areaEii`.
    pub mangled: Option<String>,
    /// The analyst's own name for the entry, when one is recorded.
    pub renamed: Option<String>,
}

impl SymbolImage {
    /// The spellings of a function, in the order a port looks for a
    /// name: the image's own first — a demangled name, then the mangled
    /// spelling — and the analyst's own last, since a rename recorded
    /// for one version names that version's address and no other.
    fn spellings(function: &SymbolFunction) -> Vec<&str> {
        let mut spelled = Vec::new();
        spelled.push(function.name.as_str());
        if let Some(mangled) = function.mangled.as_deref() {
            if mangled != function.name {
                spelled.push(mangled);
            }
        }
        if let Some(renamed) = function.renamed.as_deref() {
            // A rename that only re-spells the image's own name names
            // nothing new.
            if renamed != function.name && spelled.iter().all(|held| *held != renamed) {
                spelled.push(renamed);
            }
        }
        spelled
    }

    /// The function `name` names on this side, with the spelling it
    /// matched on; each spelling's hits in its own order, the image's
    /// own names before a rename's.
    ///
    /// The search is per-spelling: a name some image spells first and a
    /// rename spells later takes the image's own function for it,
    /// whichever spelling is searched.
    fn by_name(&self, name: &str) -> Option<&SymbolFunction> {
        // `spellings` reads the image's own names first, so a name
        // collision between two functions takes the image's own match.
        // Search each spelling's whole list in turn, so an image-name
        // hit anywhere outranks a rename on another function.
        for index in 0..3 {
            for function in &self.functions {
                let spelled = Self::spellings(function);
                if spelled.get(index) == Some(&name) {
                    return Some(function);
                }
            }
        }
        None
    }
}

/// The pairs a symbol match draws: each source function record whose
/// spellings name a destination function, and the source records no
/// destination holds, each with why.
fn match_by_symbol(
    source: &SourceProject,
    source_image: &SymbolImage,
    dest_image: &SymbolImage,
) -> (Vec<MatchedFunction>, Vec<UnmatchedFunction>) {
    let mut matched: Vec<MatchedFunction> = Vec::new();
    let mut unmatched: Vec<UnmatchedFunction> = Vec::new();
    for fun in &source.functions {
        let Some(source_address) = ag_corpus::parse_addr(&fun.address).ok() else {
            unmatched.push(UnmatchedFunction {
                source: fun.address.clone(),
                reason: "the source record's address does not read".to_string(),
            });
            continue;
        };
        let Some(source_function) = source_image
            .functions
            .iter()
            .find(|f| f.address == source_address)
            .cloned()
        else {
            unmatched.push(UnmatchedFunction {
                source: fun.address.clone(),
                reason: "the source record's entry is in no symbol the source image spells"
                    .to_string(),
            });
            continue;
        };
        let spellings = SymbolImage::spellings(&source_function);
        let mut hit = None;
        for name in &spellings {
            if let Some(dest_function) = dest_image.by_name(name) {
                hit = Some((dest_function.clone(), (*name).to_string()));
                break;
            }
        }
        match hit {
            Some((dest_function, symbol)) => matched.push(MatchedFunction {
                symbol,
                source: fun.address.clone(),
                dest: format!("{:#x}", dest_function.address),
                var_types: fun.var_types.clone(),
                stack_vars: fun.stack_vars.clone(),
            }),
            None => unmatched.push(UnmatchedFunction {
                source: fun.address.clone(),
                reason: format!(
                    "no function in the destination is named {}",
                    spellings.join(" or ")
                ),
            }),
        }
    }
    (matched, unmatched)
}

/// What a port would do, without doing it.
pub fn preview(
    source: &SourceProject,
    source_image: &SymbolImage,
    dest_image: &SymbolImage,
    held: &HeldProject,
) -> Result<PortPreview, String> {
    let (matched, unmatched) = match_by_symbol(source, source_image, dest_image);
    let mut plan = ag_image::port::carry(&matched, source, held)?;
    plan.unmatched = unmatched;
    Ok(plan)
}

/// Carry the ported types and signatures into the destination that
/// holds `held`, and say what moved and what was held back.
pub fn apply(
    source: &SourceProject,
    source_image: &SymbolImage,
    dest_image: &SymbolImage,
    held: &HeldProject,
) -> Result<PortResult, String> {
    let (matched, unmatched) = match_by_symbol(source, source_image, dest_image);
    let mut result = ag_image::port::apply(&matched, source, held)?;
    result.unmatched = unmatched;
    Ok(result)
}

/// A function's record, as a portable source project holds it: the
/// variable types and stack variables that stand on it, read off the
/// annotations of `project` as a list of canonical addresses.
pub fn source_of_project(
    project: &ag_corpus::project::ProjectFile,
) -> (SourceProject, SymbolImage) {
    let mut source = SourceProject {
        definitions: crate::types::texts(project),
        functions: Vec::new(),
    };
    let mut functions = Vec::new();
    for record in &project.annotations {
        if record.variable.is_some() || record.register.is_some() || record.block {
            continue;
        }
        let address = record.address.clone();
        let var_types: Vec<SignatureWord> = record
            .var_types
            .iter()
            .map(|word| SignatureWord {
                variable: word.variable.clone(),
                ty: word.ty.clone(),
            })
            .collect();
        let stack_vars: Vec<StackWord> = record
            .stack_vars
            .iter()
            .map(|word| StackWord {
                offset: word.offset,
                size: word.size,
                name: word.name.clone(),
                ty: word.ty.clone(),
            })
            .collect();
        if var_types.is_empty() && stack_vars.is_empty() {
            continue;
        }
        source.functions.push(FunctionRecord {
            address: address.clone(),
            var_types,
            stack_vars,
        });
        let renamed = record.name.clone();
        let address = ag_corpus::parse_addr(&address).unwrap_or(0);
        functions.push(SymbolFunction {
            address,
            name: renamed
                .clone()
                .unwrap_or_else(|| format!("sub_{address:x}")),
            mangled: None,
            renamed,
        });
    }
    // `symbol_of` names a function's source spelling: the renamed name
    // when one stands, else the address itself when nothing renames
    // it — the entry the destination image also holds is the one the
    // project renamed, and a project that renamed nothing names
    // nothing; those functions are unmatched and say so.
    (source, SymbolImage { functions })
}

/// The destination's held project: its definitions, its signatures by
/// function address, and the destination variables a port may hold.
pub fn held_of_project(project: &ag_corpus::project::ProjectFile) -> HeldProject {
    let mut signatures: BTreeMap<String, Vec<SignatureWord>> = BTreeMap::new();
    let mut stack_vars: BTreeMap<String, Vec<StackWord>> = BTreeMap::new();
    for record in &project.annotations {
        if record.variable.is_some() || record.register.is_some() || record.block {
            continue;
        }
        let address = canonical_address(&record.address).unwrap_or_else(|| record.address.clone());
        if !record.var_types.is_empty() {
            signatures.insert(
                address.clone(),
                record
                    .var_types
                    .iter()
                    .map(|word| SignatureWord {
                        variable: word.variable.clone(),
                        ty: word.ty.clone(),
                    })
                    .collect(),
            );
        }
        if !record.stack_vars.is_empty() {
            stack_vars.insert(
                address.clone(),
                record
                    .stack_vars
                    .iter()
                    .map(|word| StackWord {
                        offset: word.offset,
                        size: word.size,
                        name: word.name.clone(),
                        ty: word.ty.clone(),
                    })
                    .collect(),
            );
        }
    }
    HeldProject {
        definitions: crate::types::texts(project),
        signatures,
        stack_vars,
        declared: BTreeMap::new(),
    }
}

/// A symbol image for a binary's functions, as the image spells them:
/// each function's demangled name, its mangled spelling when the image
/// demangled one, and the analyst's name held on it.
pub fn image_of(
    image: &ag_image::Binary,
    project: Option<&ag_corpus::project::ProjectFile>,
) -> SymbolImage {
    let mut functions = Vec::new();
    for function in image.functions() {
        let renamed = project.and_then(|project| {
            let key = format!("{:#x}", function.address);
            project
                .annotation_for(&key)
                .and_then(|annotation| annotation.name.clone())
        });
        let mangled = image.mangled_name(function.address).map(str::to_string);
        functions.push(SymbolFunction {
            address: function.address,
            name: function.name.clone(),
            mangled,
            renamed,
        });
    }
    SymbolImage { functions }
}

/// The variables the image declares at each function, by canonical
/// address: a carry holds back a signature for a variable its destination
/// does not declare.
pub fn declared_of(image: &ag_image::Binary) -> BTreeMap<String, BTreeSet<String>> {
    let mut declared: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for fun in image.functions() {
        let key = format!("{:#x}", fun.address);
        if let Ok(variables) = image.variables(fun.address) {
            for variable in variables {
                declared.entry(key.clone()).or_default().insert(variable.name);
            }
        }
    }
    declared
}
