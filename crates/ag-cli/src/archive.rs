//! `ag archive` — a type archive shared across projects (#377).
//!
//! An archive is one `.agarchive` file of types — each a `name` and its
//! `c`, as a project stores them — that several projects sync with. A
//! project pushes its types in and pulls the archive's into itself;
//! `status` says where every name stands between the two sides, and a
//! name the two sides hold differently is a conflict to settle, per
//! type, with `--keep project` or `--keep archive`.
//!
//! The archive is read and written as JSON, exactly as
//! [`ag_corpus::archive::TypeArchive`] defines it. The sync itself is
//! two-sided, with no common ancestor: a name both sides hold with the
//! same `c` is in-sync, with different `c` a conflict, held on one side
//! only just its own.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;

use ag_corpus::archive::{self, ArchiveType, ConflictChoice, TypeArchive, TypeStatus, TypeSync};
use ag_corpus::project::{ProjectFile, TypeDefinition};

/// Sync a project's types with a shared archive.
#[derive(Subcommand)]
pub enum ArchiveCmd {
    /// Create the archive at the path — empty, unless `--from` seeds it
    /// with the types of a project file.
    Create {
        /// The archive to create, `FILE.agarchive`.
        archive: PathBuf,
        /// Seed it with the types a project file holds.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
    },
    /// Show the archive's types, with their C.
    Show {
        /// The archive to read.
        archive: PathBuf,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Push the project's types into the archive: every name the project
    /// holds that the archive does not hold yet goes in. A name the
    /// archive holds with a different `c` is a conflict — settled with
    /// `--keep`, or left with both sides kept and the command failing
    /// when it is not.
    Push {
        /// The project file.
        #[arg(long)]
        project: PathBuf,
        /// The archive to push into.
        archive: PathBuf,
        /// Settle conflicts this way: `project` keeps the project's `c`
        /// and overwrites the archive's, `archive` keeps the archive's
        /// and skips the project's. Without it a conflict stops the push.
        #[arg(long = "keep", value_name = "project|archive")]
        keep: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Pull the archive's types into the project: every name the archive
    /// holds that the project does not hold yet goes in.
    /// A name the project holds with a different `c` is a conflict —
    /// settled with `--keep`, or left with both sides kept and the
    /// command failing when it is not.
    Pull {
        /// The project file to pull into.
        #[arg(long)]
        project: PathBuf,
        /// The archive to pull from.
        archive: PathBuf,
        /// Settle conflicts this way: `archive` keeps the archive's `c`
        /// and overwrites the project's, `project` keeps the project's
        /// and skips the archive's. Without it a conflict stops the pull.
        #[arg(long = "keep", value_name = "project|archive")]
        keep: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Say where every name stands: in-sync, project-only, archive-only,
    /// or a conflict, in name order.
    Status {
        /// The project file.
        #[arg(long)]
        project: PathBuf,
        /// The archive to read.
        archive: PathBuf,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Settle one conflict: which side's `c` wins for `NAME`, changing
    /// only that side. `--keep project` keeps the project's `c` and
    /// replaces the archive's with it; `--keep archive` keeps the
    /// archive's and replaces the project's with it.
    Resolve {
        /// The project file.
        #[arg(long)]
        project: PathBuf,
        /// The archive to settle against.
        archive: PathBuf,
        /// The definition: `struct point`, `point`, `node_t`.
        name: String,
        /// Which side wins: `project` or `archive`.
        #[arg(long = "keep", value_name = "project|archive")]
        keep: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `ag archive …`: run one archive command.
pub fn run(cmd: ArchiveCmd) -> Result<i32> {
    match cmd {
        ArchiveCmd::Create { archive, from } => create(&archive, from.as_deref()),
        ArchiveCmd::Show { archive, json } => show(&archive, json),
        ArchiveCmd::Push {
            project,
            archive,
            keep,
            json,
        } => sync(&project, &archive, keep, json, true),
        ArchiveCmd::Pull {
            project,
            archive,
            keep,
            json,
        } => sync(&project, &archive, keep, json, false),
        ArchiveCmd::Status {
            project,
            archive,
            json,
        } => status_report(&project, &archive, json),
        ArchiveCmd::Resolve {
            project,
            archive,
            name,
            keep,
            json,
        } => resolve(&project, &archive, &name, &keep, json),
    }
}

/// Read the archive at `archive`; a missing file is an error, so a
/// mistyped path is not read as an empty, divergent archive.
fn open_archive(archive: &Path) -> Result<TypeArchive> {
    TypeArchive::load(archive)
}

/// Read the archive at `archive`, or an empty one when the path is not
/// there yet: push creates a missing archive on first write, and says so.
fn open_archive_or_new(archive: &Path) -> Result<TypeArchive> {
    match TypeArchive::load(archive) {
        Ok(held) => Ok(held),
        Err(_) if !archive.exists() => {
            eprintln!("note: {} does not exist yet; a new archive is made there", archive.display());
            Ok(TypeArchive::new())
        }
        Err(error) => Err(error),
    }
}

/// Read the project at `file`; a missing file reads as a new, empty
/// project — as [`crate::project`]'s `open_project` does — so a pull into
/// a project not yet made lands its types in the file it makes.
fn open_project_file(file: &Path) -> Result<ProjectFile> {
    if file.exists() {
        ProjectFile::load(file)
            .with_context(|| format!("reading the project file {}", file.display()))
    } else {
        Ok(ProjectFile::new(ag_corpus::project::Target::default()))
    }
}

/// The choice `--keep` names.
fn keep_choice(keep: &Option<String>) -> Result<Option<ConflictChoice>> {
    match keep {
        None => Ok(None),
        Some(word) => ConflictChoice::parse(word)
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("--keep takes project or archive, not {word:?}")),
    }
}

fn create(archive: &Path, from: Option<&Path>) -> Result<i32> {
    anyhow::ensure!(
        !archive.exists(),
        "{} already exists: remove it or choose another path",
        archive.display()
    );
    let mut created = TypeArchive::new();
    if let Some(from) = from {
        anyhow::ensure!(
            from.exists(),
            "the project file {} does not exist: --from names a file there is",
            from.display()
        );
        let project = ProjectFile::load(from)
            .with_context(|| format!("reading the project file {}", from.display()))?;
        for definition in &project.types {
            created.set(ArchiveType::from(definition.clone()));
        }
    }
    created.save(archive)?;
    println!(
        "{}: archive created with {} type{}",
        archive.display(),
        created.types.len(),
        if created.types.len() == 1 { "" } else { "s" }
    );
    Ok(0)
}

fn show(archive: &Path, json: bool) -> Result<i32> {
    let held = open_archive(archive)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&held.types).context("serializing the archive")?
        );
        return Ok(0);
    }
    if held.types.is_empty() {
        println!("{}: no types in the archive", archive.display());
    }
    for entry in &held.types {
        println!("{}\n{}\n", entry.name, entry.c);
    }
    Ok(0)
}

/// Push when `pushing` is set, pull otherwise. `keep` settles conflicts;
/// without it a conflict leaves both sides kept and the command fails.
fn sync(
    project_file: &Path,
    archive_file: &Path,
    keep: Option<String>,
    json: bool,
    pushing: bool,
) -> Result<i32> {
    let choice = keep_choice(&keep)?;
    let mut project = open_project_file(project_file)?;
    let mut archive = if pushing {
        open_archive_or_new(archive_file)?
    } else {
        open_archive(archive_file)?
    };
    let mut rows = archive::status(&project.types, &archive);
    let conflicts: Vec<String> = rows
        .iter()
        .filter(|row| row.status == TypeStatus::Conflict)
        .map(|row| row.name.clone())
        .collect();
    if !conflicts.is_empty() && choice.is_none() {
        eprintln!(
            "{} {} {}: conflict on {} — settle with --keep project or --keep archive",
            project_file.display(),
            if pushing { "push" } else { "pull" },
            archive_file.display(),
            conflicts.join(", ")
        );
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&sync_json(&rows, true, &[]))
                    .context("serializing the sync")?
            );
        } else {
            print_status(&rows, project_file, archive_file);
        }
        return Ok(1);
    }
    let mut changed = Vec::new();
    for row in &mut rows {
        // The archive's side wins where it says so, whatever the
        // direction; the opposite word keeps the receiving side's own.
        let favour = match choice {
            Some(ConflictChoice::KeepProject) => pushing,
            Some(ConflictChoice::KeepArchive) => !pushing,
            None => false,
        };
        match row.status {
            TypeStatus::InSync => {}
            TypeStatus::ProjectOnly if pushing => {
                let c = row.project.clone().unwrap_or_default();
                archive.set(ArchiveType {
                    name: row.name.clone(),
                    c,
                });
                row.status = TypeStatus::InSync;
                changed.push(row.name.clone());
            }
            TypeStatus::ArchiveOnly if !pushing => {
                let c = row.archive.clone().unwrap_or_default();
                project.types.push(TypeDefinition {
                    name: row.name.clone(),
                    c,
                });
                row.status = TypeStatus::InSync;
                changed.push(row.name.clone());
            }
            TypeStatus::ProjectOnly | TypeStatus::ArchiveOnly => {}
            TypeStatus::Conflict if favour => {
                // The push side's `c` wins: on a push that is the
                // project's, on a pull it is the archive's.
                let c = if pushing {
                    row.project.clone()
                } else {
                    row.archive.clone()
                }
                .unwrap_or_default();
                if pushing {
                    archive.set(ArchiveType {
                        name: row.name.clone(),
                        c,
                    });
                } else {
                    // Replace the project's definition of the name in
                    // its place.
                    if let Some(at) = project.types.iter().position(|held| held.name == row.name) {
                        project.types[at].c = c;
                    }
                }
                row.status = TypeStatus::InSync;
                changed.push(row.name.clone());
            }
            TypeStatus::Conflict => {}
        }
    }
    if pushing {
        archive.save(archive_file)?;
    } else {
        project.save(project_file)?;
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&sync_json(&rows, false, &changed))
                .context("serializing the sync")?
        );
        return Ok(0);
    }
    print_status(&rows, project_file, archive_file);
    let verb = if pushing { "pushed" } else { "pulled" };
    println!(
        "{} {verb} {} type{}",
        if pushing {
            archive_file.display()
        } else {
            project_file.display()
        },
        changed.len(),
        if changed.len() == 1 { "" } else { "s" }
    );
    Ok(0)
}

fn status_report(project_file: &Path, archive_file: &Path, json: bool) -> Result<i32> {
    let project = open_project_file(project_file)?;
    let archive = open_archive(archive_file)?;
    let rows = archive::status(&project.types, &archive);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&sync_json(&rows, false, &[]))
                .context("serializing the status")?
        );
        return Ok(0);
    }
    print_status(&rows, project_file, archive_file);
    let tally = |status: TypeStatus| rows.iter().filter(|row| row.status == status).count();
    println!(
        "{}: {} type{}, {} conflict{}",
        archive_file.display(),
        rows.len(),
        if rows.len() == 1 { "" } else { "s" },
        tally(TypeStatus::Conflict),
        if tally(TypeStatus::Conflict) == 1 {
            ""
        } else {
            "s"
        }
    );
    Ok(0)
}

/// Settle one conflict by changing one side alone.
fn resolve(
    project_file: &Path,
    archive_file: &Path,
    name: &str,
    keep: &str,
    json: bool,
) -> Result<i32> {
    let choice = ConflictChoice::parse(keep)
        .ok_or_else(|| anyhow::anyhow!("--keep takes project or archive, not {keep:?}"))?;
    let mut project = open_project_file(project_file)?;
    let mut archive = open_archive(archive_file)?;
    let at_project = project
        .types
        .iter()
        .position(|held| held.name == name.trim());
    let at_archive = archive.get(name.trim()).map(|entry| entry.name.clone());
    anyhow::ensure!(
        at_project.is_some() || at_archive.is_some(),
        "no type is named {}",
        name.trim()
    );
    let row = archive::status(&project.types, &archive)
        .into_iter()
        .find(|row| row.name == name.trim())
        .expect("a held name stands somewhere");
    anyhow::ensure!(
        row.status == TypeStatus::Conflict,
        "{} is {}, not a conflict: nothing to settle",
        name.trim(),
        row.status.label()
    );
    match choice {
        ConflictChoice::KeepProject => {
            let c = row.project.clone().unwrap_or_default();
            archive.set(ArchiveType {
                name: name.trim().to_string(),
                c,
            });
            archive.save(archive_file)?;
        }
        ConflictChoice::KeepArchive => {
            let c = row.archive.clone().unwrap_or_default();
            let at = at_project.expect("a conflict holds it in the project");
            project.types[at].c = c;
            project.save(project_file)?;
        }
    }
    if json {
        let after: serde_json::Value = serde_json::json!({
            "name": name.trim(),
            "keep": choice.label(),
            "status": TypeStatus::InSync.label(),
        });
        println!("{}", serde_json::to_string_pretty(&after)?);
        return Ok(0);
    }
    println!("{}: kept {}", name.trim(), choice.label());
    Ok(0)
}

fn print_status(rows: &[TypeSync], project_file: &Path, archive_file: &Path) {
    if rows.is_empty() {
        println!(
            "no types on either side ({} and {})",
            project_file.display(),
            archive_file.display()
        );
        return;
    }
    for row in rows {
        println!("  {:<24} {}", row.name, row.status.label());
    }
}

/// The rows as JSON: each name with its status and the `c` each side
/// holds, when it holds it.
fn sync_json(rows: &[TypeSync], refused: bool, changed: &[String]) -> serde_json::Value {
    let mut out = serde_json::json!({
        "types": rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "name": row.name,
                    "status": row.status.label(),
                    "project": row.project.clone(),
                    "archive": row.archive.clone(),
                })
            })
            .collect::<Vec<_>>(),
    });
    if refused {
        out["refused"] = serde_json::json!(true);
    }
    if !changed.is_empty() {
        out["changed"] = serde_json::json!(changed);
    }
    out
}
