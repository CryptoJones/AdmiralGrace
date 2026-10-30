//! `ag project` — the portable project file.
//!
//! A project file (`.agproj`) records what was analysed — the target's path
//! and SHA-256 — the analysis options the run used, and the analyst's own
//! changes. This command creates one from a target (`save`), reads one back
//! (`show`), and adds one annotation at a time (`rename`, `comment`,
//! `bookmark`) so a script or an agent can build a project without editing
//! JSON by hand.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;

use ag_corpus::project::{Annotation, ProjectFile, Target, TargetKind};

use crate::export::sha256_of;

/// What to do with a project file.
#[derive(Subcommand)]
pub enum ProjectCmd {
    /// Create a project file for a target binary.
    Save {
        /// Where to write the project file.
        #[arg(long)]
        out: PathBuf,
        /// The analysis options to record, as `NAME=VALUE` (repeatable).
        #[arg(long = "option-pair")]
        options: Vec<String>,
    },
    /// Report what a project file holds.
    Show {
        /// The project file to read.
        file: PathBuf,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Record a name for the function at an address.
    Rename {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function's address, with its space when it names one.
        address: String,
        /// The name to record.
        name: String,
    },
    /// Record a comment at an address.
    Comment {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address, with its space when it names one.
        address: String,
        /// The comment to record.
        text: String,
    },
    /// Flip a bookmark on a function.
    Bookmark {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function's address, with its space when it names one.
        address: String,
    },
}

/// Run `ag project <target> …`: the target is the binary the project describes.
pub fn run(target: PathBuf, cmd: ProjectCmd) -> Result<i32> {
    match cmd {
        ProjectCmd::Save { out, options } => save(&target, &out, options),
        ProjectCmd::Show { file, json } => show(&target, &file, json),
        ProjectCmd::Rename {
            file,
            address,
            name,
        } => edit(&target, &file, TargetKind::Function, &address, |a| {
            a.name = Some(name);
        }),
        ProjectCmd::Comment {
            file,
            address,
            text,
        } => edit(&target, &file, TargetKind::Address, &address, |a| {
            a.comment = Some(text);
        }),
        ProjectCmd::Bookmark { file, address } => {
            edit(&target, &file, TargetKind::Function, &address, |a| {
                a.bookmark = !a.bookmark;
            })
        }
    }
}

/// Create a project file for `target`, recording the option pairs.
fn save(target: &Path, out: &Path, options: Vec<String>) -> Result<i32> {
    let sha256 = sha256_of(target)?;
    let mut project = ProjectFile::new(Target {
        path: Some(target.display().to_string()),
        sha256: Some(sha256),
    });
    for pair in options {
        let (name, value) = pair
            .split_once('=')
            .with_context(|| format!("--option-pair {pair:?} is not NAME=VALUE"))?;
        project.options.insert(name.to_string(), value.to_string());
    }
    project.save(out)?;
    println!(
        "wrote {} ({} bytes of target, {} options)",
        out.display(),
        std::fs::metadata(target)?.len(),
        project.options.len()
    );
    Ok(0)
}

/// Print what the project file of `target` holds.
fn show(target: &Path, file: &Path, json: bool) -> Result<i32> {
    let project = ProjectFile::load(file)?;
    if json {
        print!("{}", project.to_json()?);
        return Ok(0);
    }
    let target_field = project
        .target
        .path
        .as_deref()
        .unwrap_or("(no path recorded)");
    println!("project of {target_field}");
    if let Some(sha) = &project.target.sha256 {
        println!("  sha256  {sha}");
    }
    for (name, value) in &project.options {
        println!("  option  {name} = {value}");
    }
    for annotation in &project.annotations {
        let mut parts = Vec::new();
        if let Some(name) = &annotation.name {
            parts.push(format!("name {name}"));
        }
        if let Some(comment) = &annotation.comment {
            parts.push(format!("comment {comment:?}"));
        }
        if annotation.bookmark {
            parts.push("bookmark".to_string());
        }
        if !annotation.tags.is_empty() {
            parts.push(format!("tags {}", annotation.tags.join(",")));
        }
        if let Some(color) = &annotation.color {
            parts.push(format!("color {color}"));
        }
        if let Some(byte_type) = &annotation.byte_type {
            parts.push(format!("type {byte_type}"));
        }
        println!(
            "  {:9} {:>16}  {}",
            kind_label(annotation.kind),
            annotation.address,
            parts.join(", ")
        );
    }
    if project.annotations.is_empty() {
        println!("  (no annotations)");
    }
    // The target argument is the file the project describes; say when it
    // no longer matches what was recorded.
    if let Some(recorded) = &project.target.sha256 {
        match sha256_of(target) {
            Ok(current) if &current != recorded => {
                println!("  note: {target:?} now hashes to {current}, not {recorded}")
            }
            Err(_) => println!("  note: {target:?} cannot be read to check its hash"),
            _ => {}
        }
    }
    Ok(0)
}

/// Change one annotation of the project of `target`, then save it back.
fn edit(
    target: &Path,
    file: &Path,
    kind: TargetKind,
    address: &str,
    change: impl FnOnce(&mut Annotation),
) -> Result<i32> {
    // The project may not exist yet: the first edit creates it from the target.
    let mut project = match ProjectFile::load(file) {
        Ok(project) => project,
        Err(_) if !file.exists() => ProjectFile::new(Target {
            path: Some(target.display().to_string()),
            sha256: sha256_of(target).ok(),
        }),
        Err(error) => return Err(error),
    };
    change(project.annotation_mut(kind, address));
    project.prune();
    project.save(file)?;
    let kept = project
        .annotations
        .iter()
        .find(|a| a.kind == kind && a.address == address);
    match kept {
        Some(a) => println!(
            "{file}: {kind} {address} now {}",
            summarize(a)
        , file = file.display(), kind = kind_label(kind)),
        None => println!(
            "{file}: {kind} {address} cleared",
            file = file.display(),
            kind = kind_label(kind)
        ),
    }
    Ok(0)
}

/// One line on what an annotation carries.
fn summarize(annotation: &Annotation) -> String {
    let mut parts = Vec::new();
    if let Some(name) = &annotation.name {
        parts.push(format!("name {name}"));
    }
    if let Some(comment) = &annotation.comment {
        parts.push(format!("comment {comment:?}"));
    }
    if annotation.bookmark {
        parts.push("bookmark".to_string());
    }
    if parts.is_empty() {
        "(empty)".to_string()
    } else {
        parts.join(", ")
    }
}

/// The kind's label, as printed.
fn kind_label(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Function => "function",
        TargetKind::Address => "address",
        TargetKind::Region => "region",
    }
}
