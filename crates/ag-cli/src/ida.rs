//! `ag ida` — read IDA databases and type libraries (#403).
//!
//! `info` reports what a `.idb`, `.i64` or `.til` holds: the IDA version
//! and image it describes, and the names, comments, functions and types
//! within. `apply` writes those into a project — the names, the comments
//! and the prototypes of the functions, and the types — filling only what
//! the analyst has not already said, the way `funcid apply` does. The
//! reading is [`ag_image::ida`]; this is the command over it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ag_corpus::project::{ProjectFile, Target, TargetKind};
use ag_image::ida::extract::{CommentKind, Idb};
use ag_image::ida::til::Til;
use ag_image::ida::types;
use anyhow::{Context, Result};
use clap::Subcommand;

use crate::project::RawArgs;

/// What to do with an IDA database or type library.
#[derive(Subcommand)]
pub enum IdaCmd {
    /// Report what a database or type library holds: the IDA version and
    /// image, and the names, comments, functions, segments and types.
    Info {
        /// The IDA database (.idb, .i64) or type library (.til) to read.
        file: PathBuf,
        /// List every name, function and type, not just the counts.
        #[arg(long)]
        list: bool,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write a database's names, comments, prototypes and types into a
    /// project. The analyst's own words are kept: a rename, a comment or a
    /// prototype already on a function stands, and the import only fills
    /// what is not said.
    Apply {
        /// The IDA database (.idb, .i64) or type library (.til) to read.
        file: PathBuf,
        /// The program image the database describes; the project is made
        /// from it when it is not there yet.
        #[arg(long)]
        binary: PathBuf,
        #[command(flatten)]
        raw: RawArgs,
        /// The project file the import goes to.
        #[arg(long)]
        project: PathBuf,
        /// Leave the types out, even where the database carries them.
        #[arg(long)]
        no_types: bool,
        /// Report the summary as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Run an `ag ida` command.
pub fn run(cmd: IdaCmd) -> Result<i32> {
    match cmd {
        IdaCmd::Info { file, list, json } => info(&file, list, json),
        IdaCmd::Apply {
            file,
            binary,
            raw,
            project,
            no_types,
            json,
        } => apply(&file, &binary, raw, &project, !no_types, json),
    }
}

/// Whether a file is a type library rather than a database.
fn is_til(file: &Path) -> bool {
    file.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("til"))
}

/// Read a database, or fail with the file's name.
fn read_idb(file: &Path) -> Result<Idb> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    Idb::parse(&bytes).with_context(|| format!("reading {}", file.display()))
}

/// Read a type library, or fail with the file's name.
fn read_til(file: &Path) -> Result<Til> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    Til::parse(&bytes).with_context(|| format!("reading {}", file.display()))
}

fn info(file: &Path, list: bool, json: bool) -> Result<i32> {
    if is_til(file) {
        let til = read_til(file)?;
        if json {
            let types: Vec<serde_json::Value> = til
                .types
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "ordinal": t.ordinal,
                        "fields": t.fields,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "file": file.display().to_string(),
                    "kind": "til",
                    "format": til.format,
                    "title": til.title,
                    "base": til.base,
                    "symbols": til.symbols.len(),
                    "types": types,
                }))?
            );
        } else {
            println!(
                "{}: type library {:?} (base {:?}), {} symbols, {} types",
                file.display(),
                til.title,
                til.base,
                til.symbols.len(),
                til.types.len()
            );
            if list {
                for t in &til.types {
                    println!("  {:>4}  {}", t.ordinal, t.name);
                }
            }
        }
        return Ok(0);
    }

    let idb = read_idb(file)?;
    let root = idb.root();
    let names = idb.names();
    let functions = idb.functions();
    let entries: Vec<_> = functions.iter().filter(|f| !f.is_tail()).collect();
    let segments = idb.segments();
    let comments = idb.comments();
    let til = idb.til_bytes().and_then(|b| Til::parse(b).ok());
    let type_count = til.as_ref().map(|t| t.types.len()).unwrap_or(0);

    if json {
        let names_json: Vec<serde_json::Value> = names
            .iter()
            .map(|(ea, name)| serde_json::json!({"address": format!("{ea:#x}"), "name": name}))
            .collect();
        let funcs_json: Vec<serde_json::Value> = entries
            .iter()
            .map(|f| {
                serde_json::json!({
                    "address": format!("{:#x}", f.start),
                    "end": format!("{:#x}", f.end),
                    "name": f.name,
                    "comment": f.comment,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file": file.display().to_string(),
                "kind": "idb",
                "wordsize": idb.wordsize(),
                "version": root.version,
                "version_string": root.version_string,
                "imagebase": format!("{:#x}", root.imagebase),
                "md5": root.md5,
                "input_file_path": root.input_file_path,
                "procname": root.procname,
                "filetype": root.filetype,
                "names": names_json,
                "functions": funcs_json,
                "segments": segments.len(),
                "comments": comments.len(),
                "types": type_count,
            }))?
        );
    } else {
        println!(
            "{}: IDA {} ({}-bit), {} imagebase {:#x}",
            file.display(),
            if root.version_string.is_empty() {
                root.version.to_string()
            } else {
                root.version_string.clone()
            },
            idb.wordsize() * 8,
            root.procname,
            root.imagebase,
        );
        if let Some(path) = &root.input_file_path {
            println!("  input: {path}");
        }
        if let Some(md5) = &root.md5 {
            println!("  md5: {md5}");
        }
        println!(
            "  {} names, {} functions, {} segments, {} comments, {} types",
            names.len(),
            entries.len(),
            segments.len(),
            comments.len(),
            type_count,
        );
        if list {
            for (ea, name) in &names {
                println!("  name {ea:#x}  {name}");
            }
            for f in &entries {
                print!("  func {:#x}  {}", f.start, f.name.as_deref().unwrap_or(""));
                if let Some(cmt) = &f.comment {
                    print!("  ; {cmt}");
                }
                println!();
            }
            if let Some(til) = &til {
                for t in &til.types {
                    println!("  type {:>4}  {}", t.ordinal, t.name);
                }
            }
        }
    }
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn apply(
    file: &Path,
    binary: &Path,
    raw: RawArgs,
    project: &Path,
    with_types: bool,
    json: bool,
) -> Result<i32> {
    // A type library carries types alone; a database carries everything.
    let (idb, til) = if is_til(file) {
        (None, Some(read_til(file)?))
    } else {
        let idb = read_idb(file)?;
        let til = idb.til_bytes().and_then(|b| Til::parse(b).ok());
        (Some(idb), til)
    };

    let existing = if project.exists() {
        Some(ProjectFile::load(project).with_context(|| format!("reading {}", project.display()))?)
    } else {
        None
    };
    let spec = raw.spec()?;
    let image = crate::image::open_image(
        binary,
        spec.clone(),
        raw.slice.clone(),
        raw.dyld_image.clone(),
        existing.as_ref(),
        Default::default(),
    )?;
    let model = image.data_model();
    let mut file_out = existing.unwrap_or_else(|| {
        let sha256 = ag_corpus::project::sha256_of(binary).ok();
        // Record how the raw bytes load, so a later read of the project
        // opens the same image under the same layout.
        let raw_target = spec.as_ref().map(|s| {
            let arch = ag_image::raw_arch(&s.language)
                .unwrap_or(&s.language)
                .to_string();
            RawArgs::target(s, &arch)
        });
        ProjectFile::new(Target {
            path: Some(binary.display().to_string()),
            sha256,
            raw: raw_target,
            slice: raw.slice.clone(),
            dyld_image: raw.dyld_image.clone(),
        })
    });

    let mut named = 0usize;
    let mut commented = 0usize;
    let mut typed = 0usize;
    let mut types_added = 0usize;
    let mut types_held = 0usize;

    if let Some(idb) = &idb {
        let entries: BTreeSet<u64> = idb
            .functions()
            .into_iter()
            .filter(|f| !f.is_tail())
            .map(|f| f.start)
            .collect();
        let kind_of = |ea: u64| {
            if entries.contains(&ea) {
                TargetKind::Function
            } else {
                TargetKind::Address
            }
        };

        // The names: a function's entry is a function record, anything
        // else an address record.
        for (ea, name) in idb.names() {
            let key = format!("{ea:#x}");
            let annotation = file_out.annotation_mut(kind_of(ea), &key);
            if annotation.name.is_none() {
                annotation.name = Some(name);
                named += 1;
            }
        }

        // The functions: their comment and their prototype.
        for f in idb.functions().iter().filter(|f| !f.is_tail()) {
            let key = format!("{:#x}", f.start);
            let annotation = file_out.annotation_mut(TargetKind::Function, &key);
            if annotation.comment.is_none() {
                let comment = f.comment.clone().or_else(|| f.repeatable_comment.clone());
                if let Some(comment) = comment {
                    annotation.comment = Some(comment);
                    commented += 1;
                }
            }
            if annotation.prototype.is_none() {
                if let Some((ti, arg_names)) = idb.function_prototype_bytes(f.start) {
                    let name = annotation
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("sub_{:x}", f.start));
                    let empty = Til::default();
                    let til_ref = til.as_ref().unwrap_or(&empty);
                    if let Some(proto) =
                        types::render_prototype(&ti, &arg_names, &name, til_ref, model)
                    {
                        annotation.prototype = Some(proto);
                        typed += 1;
                    }
                }
            }
        }

        // The address comments: anterior lines stand above the line, the
        // regular and repeatable inline, posterior lines appended. Group
        // them by address once.
        let mut by_address: std::collections::BTreeMap<u64, Vec<&ag_image::ida::extract::Comment>> =
            std::collections::BTreeMap::new();
        let all_comments = idb.comments();
        for comment in &all_comments {
            by_address.entry(comment.address).or_default().push(comment);
        }
        for (ea, comments) in by_address {
            let anterior: Vec<&str> = comments
                .iter()
                .filter(|c| c.kind == CommentKind::Anterior)
                .map(|c| c.text.as_str())
                .collect();
            let regular = comments
                .iter()
                .find(|c| c.kind == CommentKind::Regular)
                .map(|c| c.text.clone());
            let repeatable = comments
                .iter()
                .find(|c| c.kind == CommentKind::Repeatable)
                .map(|c| c.text.clone());
            let posterior: Vec<&str> = comments
                .iter()
                .filter(|c| c.kind == CommentKind::Posterior)
                .map(|c| c.text.as_str())
                .collect();
            // The analyst's regular comment comes first, inline; anterior
            // lines (often an auto-generated header) stand above only when
            // there is no regular comment; posterior lines append.
            let (text, above) = if let Some(regular) = regular.or(repeatable) {
                let mut text = regular;
                if !posterior.is_empty() {
                    text.push('\n');
                    text.push_str(&posterior.join("\n"));
                }
                (text, false)
            } else if !anterior.is_empty() {
                (anterior.join("\n"), true)
            } else {
                (posterior.join("\n"), false)
            };
            if text.is_empty() {
                continue;
            }
            let key = format!("{ea:#x}");
            let annotation = file_out.annotation_mut(kind_of(ea), &key);
            if annotation.comment.is_none() {
                annotation.comment = Some(text);
                annotation.comment_above = above;
                commented += 1;
            }
        }
    }

    // The types: render the library and add what the project does not
    // already define, in dependency order.
    if with_types {
        if let Some(til) = &til {
            let mut held = crate::types::texts(&file_out);
            for def in types::render_all(til, model) {
                match ag_image::ctype::add(model, &held, &def.c) {
                    Ok((defined, added, _notes)) => {
                        held = defined;
                        types_added += added.len();
                    }
                    Err(_) => types_held += 1,
                }
            }
            file_out.types = crate::types::definitions(&held);
        }
    }

    file_out.prune();
    file_out
        .save(project)
        .with_context(|| format!("writing {}", project.display()))?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "project": project.display().to_string(),
                "named": named,
                "commented": commented,
                "prototyped": typed,
                "types_added": types_added,
                "types_held_back": types_held,
            })
        );
    } else {
        println!(
            "{}: {} named, {} commented, {} prototyped, {} types added ({} held back)",
            project.display(),
            named,
            commented,
            typed,
            types_added,
            types_held,
        );
    }
    Ok(0)
}
