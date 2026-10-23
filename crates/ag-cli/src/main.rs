use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ag", version, about = "AdmiralGrace decompiler toolchain")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Corpus {
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

fn expand_tilde(p: &PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    p.clone()
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
    let Cmd::Corpus { root, methods, shift, cmd } = cmd;
    let root = expand_tilde(&root);
    let corpus = ag_corpus::Corpus::load(&root).context("loading corpus")?;
    let shift_val = ag_corpus::parse_addr(&shift)?;
    let overlay = match methods {
        Some(mpath) => {
            let m = ag_corpus::objc::load_map(&expand_tilde(&mpath))?;
            Some(ag_corpus::objc::Overlay::new(m).with_shift(shift_val))
        }
        None => None,
    };
    match cmd {
        CorpusCmd::Stats => {
            let s = ag_corpus::stats(&corpus);
            println!(
                "total={} written={} failed={} external={} named_distinct={} methods={}",
                s.total,
                s.written,
                s.failed,
                s.external,
                s.named_distinct,
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
            for f in &corpus.functions {
                let name = f.name.as_deref().unwrap_or("FUN_anon");
                if named_only && f.name.is_none() {
                    continue;
                }
                if with_body && !f.has_body() {
                    continue;
                }
                if let Some(re) = &re {
                    if !re.is_match(name) {
                        continue;
                    }
                }
                println!("{:#x} {:20} {}", f.address, f.status, name);
            }
        }
        CorpusCmd::Show { target } => {
            let f = resolve(&corpus, overlay.as_ref(), &target)?;
            let mut name = display_name(f, overlay.as_ref());
            name.truncate(70);
            println!("{} [{}] {}", name, f.status, format!("{:#x}", f.address));
            if let Some(r) = &f.range {
                match r {
                    ag_corpus::BodyRange::Contiguous { start, end } => {
                        println!("range: {start:#x}-{end:#x}")
                    }
                    ag_corpus::BodyRange::NonContiguous { ranges } => {
                        let rs: Vec<String> = ranges
                            .iter()
                            .map(|(s, e)| format!("{s:#x}-{e:#x}"))
                            .collect();
                        println!("ranges: {}", rs.join(", "));
                    }
                }
            }
            println!("{}", corpus.function_body(f)?);
        }
        CorpusCmd::Grep { pattern, class } => {
            let body = Regex::new(&pattern)?;
            let class_re = class.as_ref().map(|c| Regex::new(c)).transpose()?;
            for f in &corpus.functions {
                if !f.has_body() {
                    continue;
                }
                if let (Some(o), Some(cls)) = (overlay.as_ref(), class_re.as_ref()) {
                    let imp_name = match o.by_imp.get(&f.address) {
                        Some(m) => format!("{}", ag_corpus::objc::method_display(m)),
                        None => continue,
                    };
                    if !cls.is_match(&imp_name) {
                        continue;
                    }
                }
                let text = corpus.function_body(f)?;
                if body.is_match(&text) {
                    let name = display_name(f, overlay.as_ref());
                    println!("{:#x} {name}", f.address);
                }
            }
        }
    }
    Ok(())
}

fn display_name(f: &ag_corpus::Function, overlay: Option<&ag_corpus::objc::Overlay>) -> String {
    if let Some(o) = overlay {
        if let Some(m) = o.by_imp.get(&f.address) {
            return ag_corpus::objc::method_display(m);
        }
    }
    f.name.clone().unwrap_or_else(|| "FUN_anon".into())
}

fn resolve<'a>(
    corpus: &'a ag_corpus::Corpus,
    overlay: Option<&ag_corpus::objc::Overlay>,
    target: &str,
) -> Result<&'a ag_corpus::Function> {
    if target.starts_with("0x") || target.starts_with("0X") {
        let a = ag_corpus::parse_addr(target)?;
        if let Some(i) = corpus.by_address.get(&a) {
            return Ok(&corpus.functions[*i]);
        }
    }
    if let Some(o) = overlay {
        if let Some(imp) = o.by_name.get(target) {
            let addr = o.imp_addr(*imp);
            if let Some(i) = corpus.by_address.get(&addr) {
                return Ok(&corpus.functions[*i]);
            }
        }
        for (name, imp) in &o.by_name {
            if name.contains(target) {
                let addr = o.imp_addr(*imp);
                if let Some(i) = corpus.by_address.get(&addr) {
                    return Ok(&corpus.functions[*i]);
                }
            }
        }
    }
    if let Some(v) = corpus.by_name.get(target) {
        return pick_body(corpus, v);
    }
    let subs: Vec<usize> = corpus
        .functions
        .iter()
        .enumerate()
        .filter(|(_, f)| f.name.as_deref().map_or(false, |n| n.contains(target)))
        .map(|(i, _)| i)
        .collect();
    anyhow::ensure!(!subs.is_empty(), "no function matching {target:?}");
    pick_body(corpus, &subs)
}

fn pick_body<'a>(corpus: &'a ag_corpus::Corpus, idxs: &[usize]) -> Result<&'a ag_corpus::Function> {
    let f = idxs
        .iter()
        .map(|i| &corpus.functions[*i])
        .find(|f| f.has_body())
        .ok_or_else(|| anyhow::anyhow!("no body for matched functions"))?;
    Ok(f)
}
