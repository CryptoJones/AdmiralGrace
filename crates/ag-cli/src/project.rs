//! `ag project` — the portable project file.
//!
//! A project file (`.agproj`) records what was analysed — the target's path
//! and SHA-256 — the analysis options the run used, and the analyst's own
//! changes. This command creates one from a target (`save`), reads one back
//! (`show`), adds one annotation at a time (`rename`, `comment`, `bookmark`,
//! `tag`, `color`) so a script or an agent can build a project without
//! editing JSON by hand, and reports the tags the analyst gave (`tags`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};

use ag_corpus::project::{
    parse_color, parse_tags, sha256_of, Annotation, ProjectFile, Target, TargetKind,
};

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
        /// Stand the comment on its own line above the instruction, rather
        /// than inline at the end of it.
        #[arg(long)]
        above: bool,
    },
    /// Flip a bookmark on a function.
    Bookmark {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function's address, with its space when it names one.
        address: String,
    },
    /// Attach tags to, or take them off, the thing at an address.
    Tag {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address, with its space when it names one.
        address: String,
        /// The tags to attach, one word each; `a,b` is two.
        #[arg(required = true)]
        tags: Vec<String>,
        /// Take the tags off instead of attaching them.
        #[arg(long)]
        remove: bool,
        /// What the tags are on: the function entered at the address, the
        /// block of bytes starting there, or the one address.
        #[arg(long, value_enum, default_value_t = On::Address)]
        on: On,
    },
    /// Set or clear a highlight color on the thing at an address.
    Color {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address, with its space when it names one.
        address: String,
        /// The color: a name such as `red` or `amber`, `#rrggbb`, or `none`
        /// to clear it.
        color: String,
        /// What the color is on: the function entered at the address, the
        /// block of bytes starting there, or the one address.
        #[arg(long, value_enum, default_value_t = On::Address)]
        on: On,
    },
    /// Report the tags the project holds, or the places carrying one tag.
    Tags {
        /// The project file to read.
        file: PathBuf,
        /// A tag: list the places carrying it rather than every tag.
        tag: Option<String>,
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
    /// Record a name for a register as one function prints it.
    Reg {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function's address, with its space when it names one.
        address: String,
        /// The register's name, as the listing spells it: `rax`, `ebp`.
        register: String,
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
            above,
        } => edit(&target, &file, TargetKind::Address, &address, |a| {
            // An empty note is no note: it clears the comment the way the
            // workbench's empty submit does, rather than recording "".
            a.set_comment((!text.is_empty()).then_some(text), above);
        }),
        ProjectCmd::Bookmark { file, address } => {
            edit(&target, &file, TargetKind::Function, &address, |a| {
                a.bookmark = !a.bookmark;
            })
        }
        ProjectCmd::Tag {
            file,
            address,
            tags,
            remove,
            on,
        } => edit(&target, &file, on.into(), &address, |a| {
            // Each argument reads the way the workbench's prompt does, so
            // `crypto,parser` is two tags here as it is there.
            for tag in tags.iter().flat_map(|tag| parse_tags(tag)) {
                if remove {
                    a.remove_tag(&tag);
                } else {
                    a.add_tag(&tag);
                }
            }
        }),
        ProjectCmd::Tags { file, tag } => tags(&file, tag.as_deref()),
        ProjectCmd::Color {
            file,
            address,
            color,
            on,
        } => {
            // `none` clears; anything else must be a color before the file
            // is touched, so a typo is refused rather than recorded.
            let value = if color.trim().is_empty() || color.trim().eq_ignore_ascii_case("none") {
                None
            } else {
                Some(parse_color(&color).with_context(|| {
                    format!("{color:?} is not a color; use a name such as red or amber, or #rrggbb")
                })?)
            };
            edit(&target, &file, on.into(), &address, |a| a.color = value)
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
        } => edit_named(
            &target,
            &file,
            Named::Variable,
            &address,
            &variable,
            |a| a.name = Some(name),
        ),
        ProjectCmd::Reg {
            file,
            address,
            register,
            name,
        } => edit_named(
            &target,
            &file,
            Named::Register,
            &address,
            &register,
            |a| a.name = Some(name),
        ),
    }
}

/// What a tag or a color is on: the record's kind, as the command line
/// names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum On {
    /// The one address.
    Address,
    /// The function entered at the address.
    Function,
    /// The block of bytes starting at the address.
    Block,
}

impl From<On> for TargetKind {
    fn from(on: On) -> TargetKind {
        match on {
            On::Address => TargetKind::Address,
            On::Function => TargetKind::Function,
            On::Block => TargetKind::Region,
        }
    }
}

/// Which keyed-on-one-thing record an edit reaches.
enum Named {
    /// A local variable of the function at the address.
    Variable,
    /// A register as the function at the address prints it.
    Register,
}

impl Named {
    /// The kind's label, as the report prints it.
    fn label(self) -> &'static str {
        match self {
            Named::Variable => "variable",
            Named::Register => "register",
        }
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
        // A variable or register record says which thing it names; the
        // address alone would not tell it from the function's own record.
        let target = match (&annotation.variable, &annotation.register) {
            (Some(variable), _) => format!("{}::{variable}", annotation.address),
            (_, Some(register)) => format!("{}::{register}", annotation.address),
            (None, None) => annotation.address.clone(),
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

/// Print the tags of the project file, or the places carrying `tag`.
///
/// Without a tag, one line per tag with how many places carry it. With
/// one, one line per place, in address order, in the shape `show` prints a
/// record — the kind, the address, and what the record carries.
fn tags(file: &Path, tag: Option<&str>) -> Result<i32> {
    let project = ProjectFile::load(file)?;
    match tag {
        None => {
            let index = project.tags();
            for (tag, places) in &index {
                println!(
                    "  {tag:20} {places} place{}",
                    if *places == 1 { "" } else { "s" }
                );
            }
            if index.is_empty() {
                println!("  (no tags)");
            }
        }
        Some(tag) => {
            let places = project.tagged(tag);
            for annotation in &places {
                println!(
                    "  {:9} {:>16}  {}",
                    annotation.kind.label(),
                    annotation.address,
                    summarize(annotation)
                );
            }
            if places.is_empty() {
                println!("  (nothing carries the tag {tag:?})");
            }
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
    let key = ag_corpus::project::canonical_address(address).unwrap_or_else(|| address.to_string());
    // A block's record stands apart from the address's own, so the report
    // reads back the one the edit reached.
    let kept = if kind == TargetKind::Region {
        project.block_for(&key)
    } else {
        project.annotation_for(&key)
    };
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

/// Change the record that names one thing — a variable, a register — at
/// `address`, keyed on `thing` beside it.
///
/// The two records are the same shape: a name at one address, told apart
/// from the address's own record by a key of their own. The caller says
/// which record to reach and what to call the kind in the report.
fn edit_named(
    target: &Path,
    file: &Path,
    named: Named,
    address: &str,
    thing: &str,
    change: impl FnOnce(&mut Annotation),
) -> Result<i32> {
    let mut project = open_project(target, file)?;
    let key = ag_corpus::project::canonical_address(address)
        .unwrap_or_else(|| address.to_string());
    match named {
        Named::Variable => change(project.variable_mut(&key, thing)),
        Named::Register => change(project.register_mut(&key, thing)),
    }
    project.prune();
    project.save(file)?;
    let kept = match named {
        Named::Variable => project.variable_for(&key, thing),
        Named::Register => project.register_for(&key, thing),
    };
    let label = named.label();
    match kept {
        Some(a) => println!(
            "{}: {label} {key}::{thing} now {}",
            file.display(),
            summarize(a)
        ),
        None => println!("{}: {label} {key}::{thing} cleared", file.display()),
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
        // The placement is part of what the record says, so the report
        // names it: an above-comment is not the same note as an inline one.
        if annotation.comment_above {
            parts.push(format!("comment above {comment:?}"));
        } else {
            parts.push(format!("comment {comment:?}"));
        }
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
