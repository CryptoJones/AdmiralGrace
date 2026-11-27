//! `ag pdb` — read Microsoft PDB debug info and fetch symbols from a symbol server (#400).
//!
//! `info` reports what a `.pdb` holds (GUID, age, machine, functions,
//! prototypes, locals, data symbols, and C types) or inspects a PE binary's
//! CodeView `RSDS` record. `fetch` downloads a PE binary's matching PDB from
//! a symbol server (`--server` or `_NT_SYMBOL_PATH`) into the local symbol
//! cache. `apply` writes the PDB's function names, prototypes, source
//! comments, data labels, C types, and stack/register locals into a project,
//! keeping every word the analyst has already written.

use std::path::{Path, PathBuf};

use ag_corpus::project::{ProjectFile, Target, TargetKind};
use ag_image::pdb::symsrv::{
    codeview_of_bytes, default_cache_dir, fetch_pdb, find_local_pdb, parse_symbol_path,
    CodeViewInfo,
};
use ag_image::pdb::{read_pdb, LocalLocation, PdbInfo};
use anyhow::{bail, Context, Result};
use clap::Subcommand;

use crate::project::RawArgs;

const DEFAULT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

/// What to do with PDB debug info.
#[derive(Subcommand)]
pub enum PdbCmd {
    /// Report what a `.pdb` holds, or inspect a PE binary's CodeView PDB identity.
    Info {
        /// A `.pdb` file or a PE binary (`.exe`, `.dll`, `.sys`).
        file: PathBuf,
        /// Image base added to PDB RVAs when printing addresses.
        #[arg(long, default_value = "0x0")]
        base: String,
        /// List every function, local, data symbol, and C type, not just the counts.
        #[arg(long)]
        list: bool,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Download the matching PDB for a PE binary from a symbol server into
    /// the local symbol cache (or `-o FILE`).
    Fetch {
        /// The PE binary whose CodeView debug directory names the PDB.
        binary: PathBuf,
        /// Symbol server URL or local symbol store directory (repeatable).
        /// Defaults to `_NT_SYMBOL_PATH` or Microsoft's symbol server.
        #[arg(long = "server", value_name = "URL")]
        servers: Vec<String>,
        /// Local symbol cache directory (defaults to `_NT_SYMBOL_PATH` cache
        /// or `~/.cache/ag/symbols`).
        #[arg(long, value_name = "DIR")]
        cache: Option<PathBuf>,
        /// Also write the fetched PDB to this path.
        #[arg(short = 'o', long = "out", value_name = "FILE")]
        out: Option<PathBuf>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write a PDB's names, prototypes, comments, types, and locals into a
    /// project. Existing analyst annotations are preserved. If `FILE` is
    /// omitted, the binary's matching PDB is located beside it, in the
    /// symbol cache, or downloaded from `--server` / `_NT_SYMBOL_PATH`.
    Apply {
        /// The `.pdb` file to read (optional when `--server` or local cache
        /// provides it from `--binary`'s CodeView record).
        file: Option<PathBuf>,
        /// The program image the PDB describes; the project is created from
        /// it when not present yet.
        #[arg(long)]
        binary: PathBuf,
        #[command(flatten)]
        raw: RawArgs,
        /// The project file the import goes to.
        #[arg(long)]
        project: PathBuf,
        /// Symbol server URL or local store directory to fetch from when no
        /// local PDB is given (repeatable).
        #[arg(long = "server", value_name = "URL")]
        servers: Vec<String>,
        /// Local symbol cache directory.
        #[arg(long, value_name = "DIR")]
        cache: Option<PathBuf>,
        /// Leave C type definitions out, even where the PDB carries them.
        #[arg(long)]
        no_types: bool,
        /// Leave local variables out, even where the PDB carries them.
        #[arg(long)]
        no_locals: bool,
        /// Report the summary as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Run an `ag pdb` command.
pub fn run(cmd: PdbCmd) -> Result<i32> {
    match cmd {
        PdbCmd::Info {
            file,
            base,
            list,
            json,
        } => info(&file, &base, list, json),
        PdbCmd::Fetch {
            binary,
            servers,
            cache,
            out,
            json,
        } => fetch(&binary, &servers, cache.as_deref(), out.as_deref(), json),
        PdbCmd::Apply {
            file,
            binary,
            raw,
            project,
            servers,
            cache,
            no_types,
            no_locals,
            json,
        } => apply(
            file.as_deref(),
            &binary,
            raw,
            &project,
            &servers,
            cache.as_deref(),
            !no_types,
            !no_locals,
            json,
        ),
    }
}

fn resolve_cache_and_servers(
    cli_cache: Option<&Path>,
    cli_servers: &[String],
    allow_default_msdl: bool,
) -> (PathBuf, Vec<String>) {
    let env_spec = std::env::var("_NT_SYMBOL_PATH").unwrap_or_default();
    let (env_cache, env_servers) = parse_symbol_path(&env_spec);
    let cache = cli_cache
        .map(Path::to_path_buf)
        .or(env_cache)
        .unwrap_or_else(default_cache_dir);
    let mut servers = cli_servers.to_vec();
    if servers.is_empty() {
        servers = env_servers;
    }
    if servers.is_empty() && allow_default_msdl {
        servers.push(DEFAULT_SYMBOL_SERVER.to_string());
    }
    (cache, servers)
}

fn info(file: &Path, base_str: &str, list: bool, json: bool) -> Result<i32> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let base = ag_corpus::parse_addr(base_str)?;

    if let Ok(pdb) = read_pdb(&bytes, None) {
        return report_pdb_info(file, &pdb, base, list, json);
    }

    if let Ok(Some(cv)) = codeview_of_bytes(&bytes) {
        let (cache_dir, _) = resolve_cache_and_servers(None, &[], false);
        let local = find_local_pdb(Some(file), &cv, Some(&cache_dir));
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "file": file.display().to_string(),
                    "kind": "pe",
                    "codeview": {
                        "guid": cv.guid_hex,
                        "age": cv.age,
                        "id": cv.id,
                        "path": cv.path,
                        "filename": cv.filename,
                    },
                    "local_pdb": local.as_ref().map(|r| r.path.display().to_string()),
                }))?
            );
        } else {
            println!("{}: PE CodeView RSDS", file.display());
            println!("  pdb: {} (path: {})", cv.filename, cv.path);
            println!("  guid: {}  age: {}  id: {}", cv.guid_hex, cv.age, cv.id);
            if let Some(found) = local {
                println!(
                    "  local: {} ({})",
                    found.path.display(),
                    found.source
                );
            }
        }
        return Ok(0);
    }

    bail!(
        "{} is neither a PDB file nor a PE binary with CodeView debug info",
        file.display()
    );
}

fn report_pdb_info(
    file: &Path,
    pdb: &PdbInfo,
    base: u64,
    list: bool,
    json: bool,
) -> Result<i32> {
    let locals_count: usize = pdb.functions.iter().map(|f| f.locals.len()).sum();
    if json {
        let funcs_json: Vec<serde_json::Value> = pdb
            .functions
            .iter()
            .map(|f| {
                let locals: Vec<serde_json::Value> = f
                    .locals
                    .iter()
                    .map(|l| {
                        let loc = match &l.location {
                            LocalLocation::Stack { offset, size } => serde_json::json!({
                                "kind": "stack",
                                "offset": offset,
                                "size": size,
                            }),
                            LocalLocation::Register { register, size } => serde_json::json!({
                                "kind": "register",
                                "register": register,
                                "size": size,
                            }),
                        };
                        serde_json::json!({
                            "name": l.name,
                            "type": l.ctype,
                            "location": loc,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "address": format!("{:#x}", base.wrapping_add(f.rva)),
                    "rva": format!("{:#x}", f.rva),
                    "size": f.size,
                    "name": f.name,
                    "raw_name": f.raw_name,
                    "prototype": f.prototype,
                    "source": f.source,
                    "locals": locals,
                })
            })
            .collect();
        let data_json: Vec<serde_json::Value> = pdb
            .data
            .iter()
            .map(|d| {
                serde_json::json!({
                    "address": format!("{:#x}", base.wrapping_add(d.rva)),
                    "rva": format!("{:#x}", d.rva),
                    "size": d.size,
                    "name": d.name,
                    "type": d.ctype,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file": file.display().to_string(),
                "kind": "pdb",
                "guid": pdb.guid,
                "age": pdb.age,
                "signature": pdb.signature,
                "id": pdb.id,
                "machine": pdb.machine,
                "modules": pdb.modules_count,
                "locals": locals_count,
                "functions": funcs_json,
                "data": data_json,
                "types": pdb.types,
                "types_held_back": pdb.types_held_back,
            }))?
        );
        return Ok(0);
    }

    println!(
        "{}: PDB ({}), GUID {}, age {}, id {}",
        file.display(),
        pdb.machine,
        pdb.guid,
        pdb.age,
        pdb.id
    );
    println!(
        "  {} modules, {} functions, {} locals, {} data, {} types ({} held back)",
        pdb.modules_count,
        pdb.functions.len(),
        locals_count,
        pdb.data.len(),
        pdb.types.len(),
        pdb.types_held_back
    );
    if list {
        for f in &pdb.functions {
            let addr = base.wrapping_add(f.rva);
            print!("  func {addr:#x}  {}", f.name);
            if let Some(proto) = &f.prototype {
                print!("  : {proto}");
            }
            if let Some(src) = &f.source {
                print!("  [{src}]");
            }
            println!();
            for l in &f.locals {
                let where_str = match &l.location {
                    LocalLocation::Stack { offset, size } => {
                        let sign = if *offset < 0 { '-' } else { '+' };
                        format!("[sp{sign}{:#x}] {size} bytes", offset.unsigned_abs())
                    }
                    LocalLocation::Register { register, .. } => register.clone(),
                };
                println!(
                    "    local {}  {}  {}",
                    l.name,
                    where_str,
                    l.ctype.as_deref().unwrap_or("")
                );
            }
        }
        for d in &pdb.data {
            let addr = base.wrapping_add(d.rva);
            print!("  data {addr:#x}  {}", d.name);
            let mut parts = Vec::new();
            if let Some(ty) = &d.ctype {
                parts.push(ty.clone());
            }
            if let Some(sz) = d.size {
                parts.push(format!("{sz} bytes"));
            }
            if !parts.is_empty() {
                print!("  ({})", parts.join(", "));
            }
            println!();
        }
        for ty in &pdb.types {
            println!("  type {ty}");
        }
    }
    Ok(0)
}

fn fetch(
    binary: &Path,
    cli_servers: &[String],
    cli_cache: Option<&Path>,
    out: Option<&Path>,
    json: bool,
) -> Result<i32> {
    let bytes = std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
    let cv = codeview_of_bytes(&bytes)
        .map_err(anyhow::Error::msg)?
        .with_context(|| format!("{}: no CodeView RSDS debug info", binary.display()))?;

    let (cache_dir, servers) = resolve_cache_and_servers(cli_cache, cli_servers, true);
    let result = if let Some(local) = find_local_pdb(Some(binary), &cv, Some(&cache_dir)) {
        if let Some(dest) = out {
            if dest != local.path {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::copy(&local.path, dest)?;
                ag_image::pdb::symsrv::FetchResult {
                    path: dest.to_path_buf(),
                    source: local.source,
                    cached: true,
                }
            } else {
                local
            }
        } else {
            local
        }
    } else {
        fetch_pdb(&cv, &servers, &cache_dir, out).map_err(anyhow::Error::msg)?
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "binary": binary.display().to_string(),
                "guid": cv.guid_hex,
                "age": cv.age,
                "id": cv.id,
                "filename": cv.filename,
                "path": result.path.display().to_string(),
                "source": result.source,
                "cached": result.cached,
            }))?
        );
    } else {
        println!(
            "{}: {} ({}, cached={})",
            cv.filename,
            result.path.display(),
            result.source,
            result.cached
        );
    }
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn apply(
    explicit_pdb: Option<&Path>,
    binary: &Path,
    raw: RawArgs,
    project: &Path,
    cli_servers: &[String],
    cli_cache: Option<&Path>,
    with_types: bool,
    with_locals: bool,
    json: bool,
) -> Result<i32> {
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
    let image_base = image.base().unwrap_or(0);

    let binary_cv: Option<CodeViewInfo> = std::fs::read(binary)
        .ok()
        .and_then(|b| codeview_of_bytes(&b).ok().flatten());

    let (pdb_path, pdb_source) = match explicit_pdb {
        Some(path) => (path.to_path_buf(), "file".to_string()),
        None => {
            let cv = binary_cv.as_ref().with_context(|| {
                format!(
                    "{}: no PDB file passed and the image has no CodeView RSDS debug info",
                    binary.display()
                )
            })?;
            let (cache_dir, servers) = resolve_cache_and_servers(cli_cache, cli_servers, false);
            if let Some(found) = find_local_pdb(Some(binary), cv, Some(&cache_dir)) {
                (found.path, found.source)
            } else {
                let fetched =
                    fetch_pdb(cv, &servers, &cache_dir, None).map_err(anyhow::Error::msg)?;
                (fetched.path, fetched.source)
            }
        }
    };

    let pdb_bytes =
        std::fs::read(&pdb_path).with_context(|| format!("reading {}", pdb_path.display()))?;
    let pdb = read_pdb(&pdb_bytes, Some(model)).map_err(anyhow::Error::msg)?;

    let mut notes = pdb.notes.clone();
    if let Some(cv) = &binary_cv {
        if !pdb.guid.eq_ignore_ascii_case(&cv.guid_hex) {
            let note = format!(
                "PDB GUID {} does not match image CodeView GUID {}",
                pdb.guid, cv.guid_hex
            );
            eprintln!("note: {note}");
            notes.push(note);
        }
    }

    let mut file_out = existing.unwrap_or_else(|| {
        let sha256 = ag_corpus::project::sha256_of(binary).ok();
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
    let mut labeled = 0usize;
    let mut commented = 0usize;
    let mut prototyped = 0usize;
    let mut locals_added = 0usize;
    let mut types_added = 0usize;
    let mut types_held = pdb.types_held_back;

    if with_types {
        let mut held = crate::types::texts(&file_out);
        for c_def in &pdb.types {
            match ag_image::ctype::add(model, &held, c_def) {
                Ok((defined, added, _)) => {
                    held = defined;
                    types_added += added.len();
                }
                Err(_) => types_held += 1,
            }
        }
        file_out.types = crate::types::definitions(&held);
    }

    for f in &pdb.functions {
        let addr = image_base.wrapping_add(f.rva);
        let key = format!("{addr:#x}");
        {
            let annotation = file_out.annotation_mut(TargetKind::Function, &key);
            if annotation.name.is_none() {
                annotation.name = Some(f.name.clone());
                named += 1;
            }
            if annotation.prototype.is_none() {
                if let Some(proto) = &f.prototype {
                    annotation.prototype = Some(proto.clone());
                    prototyped += 1;
                }
            }
            if annotation.comment.is_none() {
                if let Some(source) = &f.source {
                    annotation.comment = Some(format!("source: {source}"));
                    commented += 1;
                }
            }
            if with_locals {
                for local in &f.locals {
                    if let LocalLocation::Stack { offset, size } = &local.location {
                        let overlaps = annotation.stack_vars.iter().any(|existing_var| {
                            existing_var.offset == *offset
                                || (existing_var.offset < *offset + i64::from(*size)
                                    && *offset
                                        < existing_var.offset + i64::from(existing_var.size))
                        });
                        if !overlaps {
                            annotation.set_stack_var(
                                *offset,
                                *size,
                                Some(&local.name),
                                local.ctype.as_deref(),
                            );
                            locals_added += 1;
                        }
                    }
                }
            }
        }
        if with_locals {
            for local in &f.locals {
                if let LocalLocation::Register { register, .. } = &local.location {
                    let var_record = file_out.variable_mut(&key, register);
                    if var_record.name.is_none() {
                        var_record.name = Some(local.name.clone());
                        locals_added += 1;
                    }
                    if let Some(ty) = &local.ctype {
                        let annotation = file_out.annotation_mut(TargetKind::Function, &key);
                        if !annotation
                            .var_types
                            .iter()
                            .any(|vt| vt.variable == *register)
                        {
                            annotation.set_var_type(register, ty);
                        }
                    }
                }
            }
        }
    }

    for d in &pdb.data {
        let addr = image_base.wrapping_add(d.rva);
        let key = format!("{addr:#x}");
        let annotation = file_out.annotation_mut(TargetKind::Address, &key);
        if annotation.name.is_none() {
            annotation.name = Some(d.name.clone());
            labeled += 1;
        }
        if annotation.comment.is_none() {
            let mut parts = Vec::new();
            if let Some(ctype) = &d.ctype {
                parts.push(ctype.clone());
            }
            if let Some(size) = d.size {
                parts.push(format!("{size} bytes"));
            }
            if !parts.is_empty() {
                annotation.comment = Some(parts.join(", "));
                commented += 1;
            }
        }
    }

    file_out.prune();
    file_out
        .save(project)
        .with_context(|| format!("writing {}", project.display()))?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "project": project.display().to_string(),
                "pdb": pdb_path.display().to_string(),
                "source": pdb_source,
                "named": named,
                "labeled": labeled,
                "commented": commented,
                "prototyped": prototyped,
                "locals_added": locals_added,
                "types_added": types_added,
                "types_held_back": types_held,
                "notes": notes,
            }))?
        );
    } else {
        println!(
            "{}: {} named, {} labeled, {} commented, {} prototyped, {} locals, {} types added ({} held back) [{}]",
            project.display(),
            named,
            labeled,
            commented,
            prototyped,
            locals_added,
            types_added,
            types_held,
            pdb_path.display(),
        );
    }
    Ok(0)
}
