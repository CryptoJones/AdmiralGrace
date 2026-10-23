use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use std::path::{Path, PathBuf};

use ag_corpus::objc::Overlay;
use ag_corpus::{BodyRange, Corpus};

#[derive(Parser)]
#[command(name = "ag", version, about = "AdmiralGrace decompiler toolchain")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Report on a decompilation corpus or a kuna project export.
    Corpus {
        /// The corpus directory, or a kuna project export directory.
        #[arg(long, default_value = "./corpus")]
        root: PathBuf,
        #[arg(long)]
        methods: Option<PathBuf>,
        /// Image-base shift applied to ObjC IMP addresses.
        #[arg(long, default_value = "0x0")]
        shift: String,
        #[command(subcommand)]
        cmd: CorpusCmd,
    },
}

#[derive(Subcommand)]
enum CorpusCmd {
    Stats,
    List {
        #[arg(long)]
        named_only: bool,
        #[arg(long)]
        with_body: bool,
        #[arg(long)]
        filter: Option<String>,
    },
    Methods {
        #[arg(long)]
        class: Option<String>,
        #[arg(long)]
        filter: Option<String>,
    },
    Show {
        #[arg()]
        target: String,
    },
    Grep {
        pattern: String,
        #[arg(long)]
        class: Option<String>,
    },
}

/// One function, as the CLI reports it.
///
/// A corpus and a kuna export describe their functions differently, but the
/// CLI reports them the same way, so both are flattened into this.
struct Entry {
    /// The function's entry address.
    address: u64,
    /// The function's own name, or an empty string when it has none.
    name: String,
    /// The analysis status of the function.
    status: String,
    /// The function's extent, when the source knows one.
    range: Option<BodyRange>,
    /// Whether the source holds a body for the function.
    has_body: bool,
}

impl Entry {
    /// Whether the function carries a name.
    fn named(&self) -> bool {
        !self.name.is_empty()
    }
}

/// Where the reported functions come from.
enum Source {
    /// A `decompile-index.json` corpus.
    Corpus(Corpus),
    /// A kuna project export.
    Kuna(ag_corpus::kuna::KunaExport),
}

impl Source {
    /// Every function the source records, in the source's own order.
    fn entries(&self) -> Vec<Entry> {
        match self {
            Source::Corpus(corpus) => corpus
                .functions
                .iter()
                .map(|f| Entry {
                    address: f.address,
                    name: f.name.clone().unwrap_or_default(),
                    status: f.status.clone(),
                    range: f.range.clone(),
                    has_body: f.has_body(),
                })
                .collect(),
            Source::Kuna(export) => export
                .functions
                .iter()
                .map(|f| Entry {
                    address: f.address,
                    name: f.name.clone(),
                    status: if f.error.is_some() {
                        "failed".to_string()
                    } else {
                        "written".to_string()
                    },
                    range: f.size.map(|size| BodyRange::Contiguous {
                        start: f.address,
                        end: f.address.saturating_add(size),
                    }),
                    has_body: f.error.is_none(),
                })
                .collect(),
        }
    }

    /// The body of the function at `index`, when the source has one.
    fn body(&self, index: usize) -> Result<Option<String>> {
        match self {
            Source::Corpus(corpus) => Ok(Some(corpus.function_body(&corpus.functions[index])?)),
            Source::Kuna(export) => export.function_body(&export.functions[index]),
        }
    }
}

fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    p.to_path_buf()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cmd_run(cli.cmd) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1)
        }
    }
}

fn cmd_run(cmd: Cmd) -> Result<()> {
    let Cmd::Corpus {
        root,
        methods,
        shift,
        cmd,
    } = cmd;
    let root = expand_tilde(&root);
    let shift_val = ag_corpus::parse_addr(&shift)?;
    let overlay = match methods {
        Some(mpath) => {
            let m = ag_corpus::objc::load_map(&expand_tilde(&mpath))?;
            Some(Overlay::new(m).with_shift(shift_val))
        }
        None => None,
    };

    // A kuna export and a corpus are two shapes of the same analysis, so the
    // same subcommands report on either.
    let source = if ag_corpus::kuna::is_kuna_export(&root) {
        Source::Kuna(ag_corpus::kuna::KunaExport::load(&root).context("loading kuna export")?)
    } else {
        Source::Corpus(Corpus::load(&root).context("loading corpus")?)
    };
    let entries = source.entries();

    match cmd {
        CorpusCmd::Stats => {
            let total = entries.len();
            let written = entries.iter().filter(|e| e.status == "written").count();
            let failed = entries.iter().filter(|e| e.status == "failed").count();
            let external = entries
                .iter()
                .filter(|e| e.name.starts_with("<EXTERNAL>"))
                .count();
            let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            names.sort_unstable();
            names.dedup();
            let named_distinct = names.len();
            println!(
                "total={} written={} failed={} external={} named_distinct={} methods={}",
                total,
                written,
                failed,
                external,
                named_distinct,
                overlay.as_ref().map_or(0, |o| o.by_name.len())
            );
        }
        CorpusCmd::Methods { class, filter } => {
            let overlay = overlay.context("--methods map required for methods listing")?;
            let re = filter.as_ref().map(|f| Regex::new(f)).transpose()?;
            let mut imp_opt = overlay.by_imp.iter().collect::<Vec<_>>();
            imp_opt.sort_by_key(|(imp, _)| **imp);
            for (imp, m) in imp_opt {
                if let Some(c) = &class {
                    if m.class != *c {
                        continue;
                    }
                }
                if let Some(re) = &re {
                    if !re.is_match(&m.sel) {
                        continue;
                    }
                }
                let types = m.types.clone().unwrap_or_default();
                let types = if types.len() > 60 {
                    types[..60].to_string()
                } else {
                    types
                };
                println!("{:#x} -[{} {}] {}", imp, m.class, m.sel, types);
            }
        }
        CorpusCmd::List {
            named_only,
            with_body,
            filter,
        } => {
            let re = match &filter {
                Some(f) => Some(Regex::new(f)?),
                None => None,
            };
            for entry in &entries {
                let name = display_name(entry, overlay.as_ref());
                if named_only && !entry.named() {
                    continue;
                }
                if with_body && !entry.has_body {
                    continue;
                }
                if let Some(re) = &re {
                    if !re.is_match(&name) {
                        continue;
                    }
                }
                println!("{:#x} {:20} {}", entry.address, entry.status, name);
            }
        }
        CorpusCmd::Show { target } => {
            let index = resolve(&entries, overlay.as_ref(), &target)?;
            let entry = &entries[index];
            let mut name = display_name(entry, overlay.as_ref());
            name.truncate(70);
            println!("{} [{}] {:#x}", name, entry.status, entry.address);
            if let Some(r) = &entry.range {
                match r {
                    BodyRange::Contiguous { start, end } => {
                        println!("range: {start:#x}-{end:#x}")
                    }
                    BodyRange::NonContiguous { ranges } => {
                        let rs: Vec<String> = ranges
                            .iter()
                            .map(|(s, e)| format!("{s:#x}-{e:#x}"))
                            .collect();
                        println!("ranges: {}", rs.join(", "));
                    }
                }
            }
            if let Some(body) = source.body(index)? {
                println!("{body}");
            }
        }
        CorpusCmd::Grep { pattern, class } => {
            let body = Regex::new(&pattern)?;
            let class_re = class.as_ref().map(|c| Regex::new(c)).transpose()?;
            for (index, entry) in entries.iter().enumerate() {
                if !entry.has_body {
                    continue;
                }
                if let (Some(o), Some(cls)) = (overlay.as_ref(), class_re.as_ref()) {
                    let imp_name = match o.by_imp.get(&entry.address) {
                        Some(m) => ag_corpus::objc::method_display(m),
                        None => continue,
                    };
                    if !cls.is_match(&imp_name) {
                        continue;
                    }
                }
                let Some(text) = source.body(index)? else {
                    continue;
                };
                if body.is_match(&text) {
                    let name = display_name(entry, overlay.as_ref());
                    println!("{:#x} {name}", entry.address);
                }
            }
        }
    }
    Ok(())
}

/// The best display name for a function.
fn display_name(entry: &Entry, overlay: Option<&Overlay>) -> String {
    if let Some(o) = overlay {
        if let Some(m) = o.by_imp.get(&entry.address) {
            return ag_corpus::objc::method_display(m);
        }
    }
    if entry.named() {
        entry.name.clone()
    } else {
        "FUN_anon".into()
    }
}

/// Find the index of the function `target` names.
fn resolve(entries: &[Entry], overlay: Option<&Overlay>, target: &str) -> Result<usize> {
    if target.starts_with("0x") || target.starts_with("0X") {
        let a = ag_corpus::parse_addr(target)?;
        if let Some(index) = entries.iter().position(|entry| entry.address == a) {
            return Ok(index);
        }
    }
    if let Some(o) = overlay {
        if let Some(imp) = o.by_name.get(target) {
            let addr = o.imp_addr(*imp);
            if let Some(index) = entries.iter().position(|entry| entry.address == addr) {
                return Ok(index);
            }
        }
        for (name, imp) in &o.by_name {
            if name.contains(target) {
                let addr = o.imp_addr(*imp);
                if let Some(index) = entries.iter().position(|entry| entry.address == addr) {
                    return Ok(index);
                }
            }
        }
    }
    if let Some(index) = entries.iter().position(|entry| entry.name == target) {
        return pick_body(entries, &[index]);
    }
    let subs: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.name.contains(target))
        .map(|(i, _)| i)
        .collect();
    anyhow::ensure!(!subs.is_empty(), "no function matching {target:?}");
    pick_body(entries, &subs)
}

/// Pick the function with a body out of the candidates.
fn pick_body(entries: &[Entry], idxs: &[usize]) -> Result<usize> {
    idxs.iter()
        .copied()
        .find(|index| entries[*index].has_body)
        .ok_or_else(|| anyhow::anyhow!("no body for matched functions"))
}
