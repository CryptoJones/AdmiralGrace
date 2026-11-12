//! `ag diff` — binary similarity and diffing between versions (#398).
//!
//! Comparing two builds of a program is how a patch is read: what stayed
//! the same, what changed, what arrived and what left. This command
//! matches the functions of one version against the other — by
//! whole-function hash, by name, then by shape, the engine's
//! [`ag_image::diff`] — and reports the pairs with their similarity, the
//! functions only one side holds, and the whole-image similarity.
//!
//! With `--apply` it carries the older version's words onto the newer
//! one's project for every matched pair: the name, the prototype and the
//! comment, and the variable types and stack variables, with every
//! definition they name. The analyst's own words win — a rename, a
//! prototype or a type already on a function stands — and a name is
//! carried only where the newer version has none of its own, so a symbol
//! the newer build spells is never hidden under the older one's. The
//! types move by the same carry `ag project types port` uses, held back
//! with a reason wherever the destination cannot hold them.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ag_corpus::project::{ProjectFile, Target, TargetKind};
use ag_image::diff::{self, DiffOptions, DiffReport, FunctionFacts};
use ag_image::Binary;
use anyhow::{Context, Result};
use clap::Args;

use crate::project::RawArgs;

/// Compare two versions of a program.
#[derive(Args)]
pub struct DiffArgs {
    /// The older version: an ELF, PE, COFF or Mach-O file, or raw bytes
    /// with `--raw`.
    pub old: PathBuf,
    /// The newer version, read the same way.
    pub new: PathBuf,
    #[command(flatten)]
    pub raw: RawArgs,
    /// The older version's project file: its renames name functions for
    /// the match, and its annotations are what `--apply` carries.
    #[arg(long)]
    pub project_old: Option<PathBuf>,
    /// The newer version's project file: its renames name functions for
    /// the match, and `--apply` writes to it. Made from the image when it
    /// is not there yet.
    #[arg(long)]
    pub project_new: Option<PathBuf>,
    /// Carry the older version's names, prototypes, comments and types
    /// onto the newer version's project for every matched pair.
    #[arg(long, requires = "project_new")]
    pub apply: bool,
    /// The lowest similarity a structural match is drawn at, between 0
    /// and 1; a name or a hash is believed however the code changed.
    #[arg(long, default_value_t = diff::MIN_SIMILARITY)]
    pub min_similarity: f64,
    /// Report the comparison as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Run `ag diff`.
pub fn run(args: DiffArgs) -> Result<i32> {
    anyhow::ensure!(
        (0.0..=1.0).contains(&args.min_similarity),
        "--min-similarity is between 0 and 1, not {}",
        args.min_similarity
    );
    let old_project = match &args.project_old {
        Some(path) => {
            Some(ProjectFile::load(path).with_context(|| format!("reading {}", path.display()))?)
        }
        None => None,
    };
    let new_project = match &args.project_new {
        Some(path) if path.exists() => {
            Some(ProjectFile::load(path).with_context(|| format!("reading {}", path.display()))?)
        }
        _ => None,
    };
    let spec = args.raw.spec()?;
    let old_image = crate::image::open_image(
        &args.old,
        spec.clone(),
        args.raw.slice.clone(),
        old_project.as_ref(),
        Default::default(),
    )?;
    let new_image = crate::image::open_image(
        &args.new,
        spec,
        args.raw.slice.clone(),
        new_project.as_ref(),
        Default::default(),
    )?;

    let mut old_facts = diff::facts_of(&old_image);
    let mut new_facts = diff::facts_of(&new_image);
    diff::rename_facts(&mut old_facts, &renames_of(old_project.as_ref()));
    diff::rename_facts(&mut new_facts, &renames_of(new_project.as_ref()));
    let report = diff::diff(
        &old_facts,
        &new_facts,
        &DiffOptions {
            min_similarity: args.min_similarity,
        },
    );

    let applied = if args.apply {
        let path = args.project_new.as_ref().expect("--apply requires --project-new");
        let mut file = new_project.unwrap_or_else(|| {
            let sha256 = ag_corpus::project::sha256_of(&args.new).ok();
            ProjectFile::new(Target {
                path: Some(args.new.display().to_string()),
                sha256,
                raw: None,
                slice: None,
            })
        });
        let carried = carry(
            &report,
            &old_facts,
            &new_facts,
            old_project.as_ref(),
            &new_image,
            &mut file,
        )?;
        file.save(path)
            .with_context(|| format!("writing {}", path.display()))?;
        Some((path.clone(), carried))
    } else {
        None
    };

    if args.json {
        println!("{}", report_json(&args, &report, &old_facts, &new_facts, applied.as_ref())?);
    } else {
        print_text(&args, &report, &old_facts, &new_facts, applied.as_ref());
    }
    Ok(0)
}

/// The analyst's renames a project holds, by function entry: a rename
/// recorded for a function is its name for the comparison.
fn renames_of(project: Option<&ProjectFile>) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    let Some(project) = project else {
        return out;
    };
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

/// What a carry moved: the counts the report names.
struct Carried {
    named: usize,
    prototyped: usize,
    commented: usize,
    types_added: Vec<String>,
    signatures: usize,
    held_types: usize,
    held_signatures: usize,
}

/// Carry the older version's words onto the newer version's project for
/// every matched pair. The facts already read the renames over the image
/// names, so a name is carried only where the newer version has none of
/// its own; the prototypes, comments and types come from the older
/// project's records, and the types move by the port's own carry, held
/// back with a reason wherever the destination cannot hold them.
fn carry(
    report: &DiffReport,
    old_facts: &[FunctionFacts],
    new_facts: &[FunctionFacts],
    old_project: Option<&ProjectFile>,
    new_image: &Binary,
    new_project: &mut ProjectFile,
) -> Result<Carried> {
    let old_name = |address: u64| -> Option<String> {
        old_facts
            .iter()
            .find(|f| f.address == address)
            .and_then(|f| f.name.clone())
    };
    let new_named = |address: u64| -> bool {
        new_facts
            .iter()
            .find(|f| f.address == address)
            .is_some_and(|f| f.name.is_some())
    };

    let mut carried = Carried {
        named: 0,
        prototyped: 0,
        commented: 0,
        types_added: Vec::new(),
        signatures: 0,
        held_types: 0,
        held_signatures: 0,
    };

    // The names, prototypes and comments of the matched pairs.
    for pair in &report.matched {
        let key = format!("{:#x}", pair.new.address);
        let annotation = new_project.annotation_mut(TargetKind::Function, &key);
        if annotation.name.is_none() && !new_named(pair.new.address) {
            if let Some(name) = old_name(pair.old.address) {
                annotation.name = Some(name);
                carried.named += 1;
            }
        }
        if let Some(old_project) = old_project {
            let old_key = format!("{:#x}", pair.old.address);
            if let Some(old) = old_project.annotation_for(&old_key) {
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
    }

    // The types: the older project's records, carried over the matched
    // pairs by the port's own carry.
    if let Some(old_project) = old_project {
        let (source, _) = crate::port::source_of_project(old_project);
        let mut matched = Vec::new();
        for pair in &report.matched {
            let old_key = format!("{:#x}", pair.old.address);
            let Some(record) = source.functions.iter().find(|f| f.address == old_key) else {
                continue;
            };
            matched.push(ag_image::port::MatchedFunction {
                symbol: old_name(pair.old.address)
                    .unwrap_or_else(|| format!("sub_{:x}", pair.old.address)),
                source: old_key,
                dest: format!("{:#x}", pair.new.address),
                var_types: record.var_types.clone(),
                stack_vars: record.stack_vars.clone(),
            });
        }
        if !matched.is_empty() {
            let mut held = crate::port::held_of_project(new_project);
            held.declared = crate::port::declared_of(new_image);
            let result = ag_image::port::apply(&matched, &source, &held)
                .map_err(anyhow::Error::msg)?;
            new_project.types = crate::types::definitions(&result.definitions);
            for word in &result.applied {
                new_project
                    .annotation_mut(TargetKind::Function, &word.address)
                    .set_var_type(&word.variable, &word.ty);
            }
            for stack in &result.applied_stack {
                new_project
                    .annotation_mut(TargetKind::Function, &stack.address)
                    .set_stack_var(
                        stack.word.offset,
                        stack.word.size,
                        stack.word.name.as_deref(),
                        stack.word.ty.as_deref(),
                    );
            }
            carried.types_added = result.added.clone();
            carried.signatures = result.applied.len() + result.applied_stack.len();
            carried.held_types = result.held_types.len();
            carried.held_signatures = result.held_signatures.len();
            for held in &result.held_types {
                eprintln!("note: {}: held back ({})", held.name, held.reason);
            }
            for held in &result.held_signatures {
                eprintln!(
                    "note: {} {}: held back ({})",
                    held.function, held.variable, held.reason
                );
            }
        }
    }
    new_project.prune();
    Ok(carried)
}

/// The facts of the function at `address`, when one side holds it.
fn facts_at(facts: &[FunctionFacts], address: u64) -> Option<&FunctionFacts> {
    facts.iter().find(|f| f.address == address)
}

/// The name a report spells for a function: its own when it has one, the
/// placeholder the analysis gives otherwise.
fn spelled(facts: &[FunctionFacts], address: u64) -> String {
    facts_at(facts, address)
        .and_then(|f| f.name.clone())
        .unwrap_or_else(|| format!("sub_{address:x}"))
}

fn print_text(
    args: &DiffArgs,
    report: &DiffReport,
    old_facts: &[FunctionFacts],
    new_facts: &[FunctionFacts],
    applied: Option<&(PathBuf, Carried)>,
) {
    let unchanged = report.matched.iter().filter(|p| !p.changed()).count();
    let changed = report.matched.len() - unchanged;
    println!(
        "{} vs {}: {:.0}% similar — {} matched ({} unchanged, {} changed), {} removed, {} added",
        args.old.display(),
        args.new.display(),
        report.similarity * 100.0,
        report.matched.len(),
        unchanged,
        changed,
        report.removed.len(),
        report.added.len(),
    );
    for pair in &report.matched {
        println!(
            "  {:#x} {} -> {:#x} {}  {:.2} {}",
            pair.old.address,
            spelled(old_facts, pair.old.address),
            pair.new.address,
            spelled(new_facts, pair.new.address),
            pair.similarity,
            pair.kind.label(),
        );
    }
    if !report.removed.is_empty() {
        println!("removed:");
        for function in &report.removed {
            println!("  {:#x} {}", function.address, spelled(old_facts, function.address));
        }
    }
    if !report.added.is_empty() {
        println!("added:");
        for function in &report.added {
            println!("  {:#x} {}", function.address, spelled(new_facts, function.address));
        }
    }
    if let Some((path, carried)) = applied {
        println!(
            "{}: {} named, {} prototyped, {} commented, {} type{} added, {} signature{} carried ({} held back)",
            path.display(),
            carried.named,
            carried.prototyped,
            carried.commented,
            carried.types_added.len(),
            if carried.types_added.len() == 1 { "" } else { "s" },
            carried.signatures,
            if carried.signatures == 1 { "" } else { "s" },
            carried.held_types + carried.held_signatures,
        );
    }
}

fn report_json(
    args: &DiffArgs,
    report: &DiffReport,
    old_facts: &[FunctionFacts],
    new_facts: &[FunctionFacts],
    applied: Option<&(PathBuf, Carried)>,
) -> Result<String> {
    let matched: Vec<serde_json::Value> = report
        .matched
        .iter()
        .map(|pair| {
            let old = facts_at(old_facts, pair.old.address);
            let new = facts_at(new_facts, pair.new.address);
            serde_json::json!({
                "old_address": format!("{:#x}", pair.old.address),
                "old_name": spelled(old_facts, pair.old.address),
                "new_address": format!("{:#x}", pair.new.address),
                "new_name": spelled(new_facts, pair.new.address),
                "similarity": pair.similarity,
                "kind": pair.kind.label(),
                "changed": pair.changed(),
                "old_length": old.map(|f| f.length),
                "new_length": new.map(|f| f.length),
                "old_blocks": old.map(|f| f.blocks),
                "new_blocks": new.map(|f| f.blocks),
                "old_instructions": old.map(|f| f.instructions),
                "new_instructions": new.map(|f| f.instructions),
            })
        })
        .collect();
    let side = |functions: &[ag_image::diff::FunctionRef], facts: &[FunctionFacts]| -> Vec<serde_json::Value> {
        functions
            .iter()
            .map(|f| {
                serde_json::json!({
                    "address": format!("{:#x}", f.address),
                    "name": spelled(facts, f.address),
                })
            })
            .collect()
    };
    let mut out = serde_json::json!({
        "old": args.old.display().to_string(),
        "new": args.new.display().to_string(),
        "similarity": report.similarity,
        "matched": matched,
        "removed": side(&report.removed, old_facts),
        "added": side(&report.added, new_facts),
    });
    if let Some((path, carried)) = applied {
        out["applied"] = serde_json::json!({
            "project": path.display().to_string(),
            "named": carried.named,
            "prototyped": carried.prototyped,
            "commented": carried.commented,
            "types_added": carried.types_added,
            "signatures": carried.signatures,
            "held_types": carried.held_types,
            "held_signatures": carried.held_signatures,
        });
    }
    Ok(serde_json::to_string_pretty(&out)?)
}
