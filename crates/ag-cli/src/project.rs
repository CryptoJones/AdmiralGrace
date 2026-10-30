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

use ag_corpus::project::{sha256_of, Annotation, ProjectFile, Target, TargetKind};

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
        /// Write over an existing file, which `save` would otherwise replace
        /// without warning.
        #[arg(long)]
        force: bool,
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
    /// Record a name for the label at an address.
    ///
    /// The entry label of a function and the function's name are the same
    /// record; `label` is the spelling for a name at an address that is not
    /// a function entry.
    Label {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address, with its space when it names one.
        address: String,
        /// The name to record.
        name: String,
    },
    /// Record a name for a local variable of the function at an address.
    Var {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function's address, with its space when it names one.
        address: String,
        /// The variable's declared name, as the pseudocode writes it.
        variable: String,
        /// The name to record.
        name: String,
    },
}

/// Run `ag project <target> …`: the target is the binary the project describes.
pub fn run(target: PathBuf, cmd: ProjectCmd) -> Result<i32> {
    match cmd {
        ProjectCmd::Save {
            out,
            options,
            force,
        } => save(&target, &out, options, force),
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
        ProjectCmd::Label {
            file,
            address,
            name,
        } => edit(&target, &file, TargetKind::Address, &address, |a| {
            a.name = Some(name);
        }),
        ProjectCmd::Var {
            file,
            address,
            variable,
            name,
        } => edit_variable(&target, &file, &address, &variable, |a| {
            a.name = Some(name);
        }),
    }
}

/// Create a project file for `target`, recording the option pairs.
///
/// A `save` onto an existing file replaces it — and with it every annotation
/// it holds — so the file is refused unless `--force` says the analyst meant
/// it, the way `ag image export` refuses a non-empty directory.
fn save(target: &Path, out: &Path, options: Vec<String>, force: bool) -> Result<i32> {
    if out.exists() && !force {
        anyhow::bail!(
            "{} exists; its annotations would be replaced. Pass --force to write it anyway.",
            out.display()
        );
    }
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
        // A variable record says which variable it names; the address alone
        // would not tell it from the function's own record.
        let target = match &annotation.variable {
            Some(variable) => format!("{}::{variable}", annotation.address),
            None => annotation.address.clone(),
        };
        println!(
            "  {:9} {:>16}  {}",
            annotation.kind.label(),
            target,
            summarize(annotation)
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
    let mut project = open_project(target, file)?;
    change(project.annotation_mut(kind, address));
    project.prune();
    project.save(file)?;
    let key = ag_corpus::project::canonical_address(address)
        .unwrap_or_else(|| address.to_string());
    let kept = project.annotation_for(&key);
    match kept {
        Some(a) => println!(
            "{}: {} {key} now {}",
            file.display(),
            kind.label(),
            summarize(a)
        ),
        None => println!("{}: {} {key} cleared", file.display(), kind.label()),
    }
    Ok(0)
}

/// Change the record naming the local variable `variable` at `address`.
fn edit_variable(
    target: &Path,
    file: &Path,
    address: &str,
    variable: &str,
    change: impl FnOnce(&mut Annotation),
) -> Result<i32> {
    let mut project = open_project(target, file)?;
    change(project.variable_mut(address, variable));
    project.prune();
    project.save(file)?;
    let key = ag_corpus::project::canonical_address(address)
        .unwrap_or_else(|| address.to_string());
    let kept = project.variable_for(&key, variable);
    match kept {
        Some(a) => println!(
            "{}: variable {key}::{variable} now {}",
            file.display(),
            summarize(a)
        ),
        None => println!("{}: variable {key}::{variable} cleared", file.display()),
    }
    Ok(0)
}

/// The project of `file`, created from `target` when the file is not there.
fn open_project(target: &Path, file: &Path) -> Result<ProjectFile> {
    // The project may not exist yet: the first edit creates it from the target.
    match ProjectFile::load(file) {
        Ok(project) => Ok(project),
        Err(_) if !file.exists() => {
            let sha256 = match sha256_of(target) {
                Ok(sha) => Some(sha),
                Err(error) => {
                    eprintln!("note: {target:?} cannot be hashed to record: {error:#}");
                    None
                }
            };
            Ok(ProjectFile::new(Target {
                path: Some(target.display().to_string()),
                sha256,
            }))
        }
        Err(error) => Err(error),
    }
}

/// What an annotation carries, as one comma-separated line.
///
/// `show` prints an annotation with this, and `edit` confirms with it, so the
/// two can never disagree about what a record holds.
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
    if !annotation.tags.is_empty() {
        parts.push(format!("tags {}", annotation.tags.join(",")));
    }
    if let Some(color) = &annotation.color {
        parts.push(format!("color {color}"));
    }
    if let Some(byte_type) = &annotation.byte_type {
        parts.push(format!("type {byte_type}"));
    }
    if parts.is_empty() {
        "(empty)".to_string()
    } else {
        parts.join(", ")
    }
}
