//! The version comparison (#398): another version of the open program,
//! the matches between them, and the carry of the other version's words
//! onto this one.
//!
//! The open program is the new side of the comparison and the version
//! opened beside it the old: the matches read from the other version to
//! this one, and an apply carries the other version's names, prototypes,
//! comments and types onto the open program's annotations — the same
//! carry `ag diff --apply` makes, with the analyst's own words winning
//! and a name carried only where this version has none of its own.
//!
//! The project adapters below mirror the command line's (`ag-cli`'s
//! `port`): the carry itself is [`ag_image::port`], shared by both, but
//! reading a project file into its shape needs `ag-corpus`, which the
//! image crate does not depend on.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use ag_corpus::project::{canonical_address, ProjectFile, TargetKind};
use ag_image::diff::{DiffReport, FunctionFacts};
use ag_image::port::{
    FunctionRecord, HeldProject, MatchedFunction, SignatureWord, SourceProject, StackWord,
};
use ag_image::TypeText;

/// Another version of the open program, and the comparison between them.
#[derive(Debug, Clone)]
pub struct DiffState {
    /// The other version's image.
    pub binary: Arc<ag_image::Binary>,
    /// The path it was read from.
    pub path: PathBuf,
    /// The other version's project: its renames named functions for the
    /// match, and its annotations are what an apply carries over.
    pub project: ProjectFile,
    /// Where that project was read from, when one was named.
    pub project_path: Option<PathBuf>,
    /// The matches: the other version is the old side, the open program
    /// the new.
    pub report: DiffReport,
    /// The other version's facts, as the match read them.
    pub facts: Vec<FunctionFacts>,
    /// The open program's facts, its renames read over the image names.
    pub new_facts: Vec<FunctionFacts>,
    /// The pair chosen for the side-by-side view, by its place in the
    /// report's matched list.
    pub selected: Option<usize>,
}

/// The analyst's renames a project holds, by function entry: a rename
/// recorded for a function is its name for the comparison.
pub fn renames_of(project: &ProjectFile) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    for record in &project.annotations {
        if record.variable.is_some() || record.register.is_some() || record.block {
            continue;
        }
        if let Some(name) = &record.name {
            if let Ok(address) = ag_corpus::parse_addr(&record.address) {
                out.insert(address, name.clone());
            }
        }
    }
    out
}

/// The definitions a project holds, as the carry reads them.
fn texts(project: &ProjectFile) -> Vec<TypeText> {
    project
        .types
        .iter()
        .map(|d| TypeText {
            name: d.name.clone(),
            c: d.c.clone(),
        })
        .collect()
}

/// The source side of a carry: the other version's definitions and the
/// function records that hold a type or a stack variable.
fn source_of(project: &ProjectFile) -> SourceProject {
    let mut functions = Vec::new();
    for record in &project.annotations {
        if record.variable.is_some() || record.register.is_some() || record.block {
            continue;
        }
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
        functions.push(FunctionRecord {
            address: record.address.clone(),
            var_types,
            stack_vars,
        });
    }
    SourceProject {
        definitions: texts(project),
        functions,
    }
}

/// The held side of the open program: its definitions and the words
/// already on its functions. `declared` is filled by the caller from the
/// open image, which the project file does not hold.
fn held_of(project: &ProjectFile) -> HeldProject {
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
        definitions: texts(project),
        signatures,
        stack_vars,
        declared: BTreeMap::new(),
    }
}

/// What a carry moved: the counts the notice names.
#[derive(Debug, Default, Clone, Copy)]
pub struct Carried {
    /// Functions named that had no name of their own.
    pub named: usize,
    /// Prototypes carried onto functions that had none.
    pub prototyped: usize,
    /// Comments carried onto functions that had none.
    pub commented: usize,
    /// Definitions added to the project's types.
    pub types_added: usize,
    /// Variable and stack words carried.
    pub signatures: usize,
    /// Types and signatures held back, with a reason.
    pub held: usize,
}

/// Carry the other version's words onto the open program's annotations
/// for every matched pair: the name where this version has none of its
/// own, the prototype and comment where this version has none, and the
/// types by the port's own carry, held back with a reason wherever this
/// version cannot hold them. The analyst's own words win throughout.
pub fn carry(
    state: &DiffState,
    dest: &mut ProjectFile,
    declared: BTreeMap<String, BTreeSet<String>>,
) -> Result<Carried, String> {
    let old_name = |address: u64| -> Option<String> {
        state
            .facts
            .iter()
            .find(|f| f.address == address)
            .and_then(|f| f.name.clone())
    };
    let new_named = |address: u64| -> bool {
        state
            .new_facts
            .iter()
            .find(|f| f.address == address)
            .is_some_and(|f| f.name.is_some())
    };

    let mut carried = Carried::default();

    // The names, prototypes and comments of the matched pairs.
    for pair in &state.report.matched {
        let key = format!("{:#x}", pair.new.address);
        let annotation = dest.annotation_mut(TargetKind::Function, &key);
        if annotation.name.is_none() && !new_named(pair.new.address) {
            if let Some(name) = old_name(pair.old.address) {
                annotation.name = Some(name);
                carried.named += 1;
            }
        }
        let old_key = format!("{:#x}", pair.old.address);
        if let Some(old) = state.project.annotation_for(&old_key) {
            if annotation.prototype.is_none() {
                if let Some(prototype) = &old.prototype {
                    annotation.prototype = Some(prototype.clone());
                    carried.prototyped += 1;
                }
            }
            if annotation.comment.is_none() {
                if let Some(comment) = &old.comment {
                    annotation.comment = Some(comment.clone());
                    carried.commented += 1;
                }
            }
        }
    }

    // The types: the other version's records, carried over the matched
    // pairs by the port's own carry.
    let source = source_of(&state.project);
    let mut matched = Vec::new();
    for pair in &state.report.matched {
        let old_key = format!("{:#x}", pair.old.address);
        let Some(record) = source.functions.iter().find(|f| f.address == old_key) else {
            continue;
        };
        matched.push(MatchedFunction {
            symbol: old_name(pair.old.address)
                .unwrap_or_else(|| format!("sub_{:x}", pair.old.address)),
            source: old_key,
            dest: format!("{:#x}", pair.new.address),
            var_types: record.var_types.clone(),
            stack_vars: record.stack_vars.clone(),
        });
    }
    if !matched.is_empty() {
        let mut held = held_of(dest);
        held.declared = declared;
        let result = ag_image::port::apply(&matched, &source, &held)?;
        dest.types = result
            .definitions
            .iter()
            .map(|d| ag_corpus::project::TypeDefinition {
                name: d.name.clone(),
                c: d.c.clone(),
            })
            .collect();
        for word in &result.applied {
            dest.annotation_mut(TargetKind::Function, &word.address)
                .set_var_type(&word.variable, &word.ty);
        }
        for stack in &result.applied_stack {
            dest.annotation_mut(TargetKind::Function, &stack.address)
                .set_stack_var(
                    stack.word.offset,
                    stack.word.size,
                    stack.word.name.as_deref(),
                    stack.word.ty.as_deref(),
                );
        }
        carried.types_added = result.added.len();
        carried.signatures = result.applied.len() + result.applied_stack.len();
        carried.held = result.held_types.len() + result.held_signatures.len();
    }
    dest.prune();
    Ok(carried)
}
