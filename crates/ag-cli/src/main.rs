use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use std::path::{Path, PathBuf};

use ag_corpus::objc::Overlay;
use ag_corpus::{BodyRange, Corpus};

mod catalog;
mod docs;
mod export;
mod image;
mod project;
mod skill;

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
    /// Install the agent skill, embedded in this binary.
    InstallSkill {
        /// The agent to install for.
        #[arg(long)]
        agent: Option<skill::Agent>,
        /// Install into the current directory, to commit alongside a repo.
        #[arg(long)]
        project: bool,
        /// Install into DIR/<skill-name>/, for any other agent.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Replace an installed copy that differs.
        #[arg(long)]
        force: bool,
        /// Write the skill to stdout and install nothing.
        #[arg(long)]
        print: bool,
    },
    /// Print the embedded manual.
    Docs {
        /// The topic to print; without one, the topics are listed.
        topic: Option<String>,
    },
    /// Report on a program image: an ELF, PE, COFF or Mach-O file, or raw
    /// bytes with `--raw`.
    Image {
        /// The program image to read.
        binary: PathBuf,
        #[command(flatten)]
        raw: project::RawArgs,
        #[command(subcommand)]
        cmd: image::ImageCmd,
    },
    /// The portable project file: the analysis's identity and the analyst's changes.
    Project {
        /// The target binary the project describes.
        binary: PathBuf,
        #[command(flatten)]
        raw: project::RawArgs,
        #[command(subcommand)]
        cmd: project::ProjectCmd,
    },
    /// Assemble one instruction to its bytes, as it would sit at an address.
    Asm {
        /// The instruction, in Intel syntax: `mov eax, 1`, `jmp 0x401010`.
        text: String,
        /// The address the instruction sits at, which a branch is encoded
        /// against.
        #[arg(long, default_value = "0")]
        at: String,
        /// The width of the program: 64 or 32.
        #[arg(long, default_value_t = 64)]
        bits: u32,
    },
    /// The engine's options: every judgment call it makes, with its symptoms.
    Catalog {
        /// Print the rows as JSON.
        #[arg(long, conflicts_with_all = ["markdown", "check"])]
        json: bool,
        /// Print the document, symptom index first. The default.
        #[arg(long, conflicts_with = "check")]
        markdown: bool,
        /// Compare the committed document with the generated one; exit 1 when it is stale.
        #[arg(long)]
        check: bool,
        /// The committed document `--check` reads.
        #[arg(long, default_value = "docs/options.md", requires = "check")]
        path: PathBuf,
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
        /// The function to show: an address, a name, or a qualified method
        /// name such as `-[NSString length]`.
        #[arg(allow_hyphen_values = true)]
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
    /// The address space the source wrote the address in, when it named one.
    space: Option<String>,
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

    /// The address as the source wrote it: `EXTERNAL:0x1` when it names a
    /// space, plain `0x1` when it does not.
    fn display_address(&self) -> String {
        match &self.space {
            Some(space) => format!("{space}:{:#x}", self.address),
            None => format!("{:#x}", self.address),
        }
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
                    space: f.space.clone(),
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
                    space: None,
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
        Ok(0) => Ok(()),
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1)
        }
    }
}

fn cmd_run(cmd: Cmd) -> Result<i32> {
    match cmd {
        Cmd::Corpus {
            root,
            methods,
            shift,
            cmd,
        } => corpus(root, methods, shift, cmd),
        Cmd::InstallSkill {
            agent,
            project,
            dir,
            force,
            print,
        } => Ok(skill::run(agent, project, dir, force, print)),
        Cmd::Docs { topic } => Ok(docs::run(topic.as_deref())),
        Cmd::Image { binary, raw, cmd } => image::run(&binary, raw.spec()?, cmd),
        Cmd::Asm { text, at, bits } => {
            let address = ag_corpus::parse_addr(&at)?;
            let bitness = match bits {
                64 => ag_image::Bitness::Bits64,
                32 => ag_image::Bitness::Bits32,
                _ => anyhow::bail!("--bits takes 64 or 32"),
            };
            let bytes = ag_image::assemble(&text, address, bitness)?;
            println!("{}", ag_corpus::project::hex_of_bytes(&bytes));
            Ok(0)
        }
        Cmd::Project { binary, raw, cmd } => project::run(binary, raw.spec()?, cmd),
        Cmd::Catalog {
            json,
            markdown: _,
            check,
            path,
        } => {
            let format = if json {
                catalog::Format::Json
            } else {
                catalog::Format::Markdown
            };
            catalog::run(format, check.then_some(path.as_path()))
        }
    }
}

/// Report on a corpus or a kuna project export.
fn corpus(root: PathBuf, methods: Option<PathBuf>, shift: String, cmd: CorpusCmd) -> Result<i32> {
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

    // What the loader had to say about the data it read is said here too:
    // nothing was dropped in silence.
    if let Source::Corpus(corpus) = &source {
        for warning in &corpus.warnings {
            eprintln!("warning: {warning}");
        }
    }
    if let Some(overlay) = &overlay {
        for warning in &overlay.warnings {
            eprintln!("warning: {warning}");
        }
    }

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
                let types = truncate_chars(&types, 60);
                println!(
                    "{:#x} {} {}",
                    imp,
                    ag_corpus::objc::method_display(m),
                    types
                );
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
                println!("{} {:20} {}", entry.display_address(), entry.status, name);
            }
        }
        CorpusCmd::Show { target } => {
            let index = resolve(&entries, overlay.as_ref(), &target)?;
            let entry = &entries[index];
            let name = display_name(entry, overlay.as_ref());
            let name = truncate_chars(&name, 70);
            println!("{} [{}] {}", name, entry.status, entry.display_address());
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
                    println!("{} {name}", entry.display_address());
                }
            }
        }
    }
    Ok(0)
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
///
/// A target that reads as an address is looked for as one first — `0x1000`,
/// `0X1000`, or a bare hexadecimal number. An address that names no function
/// is not an error: the target may still be a name.
fn resolve(entries: &[Entry], overlay: Option<&Overlay>, target: &str) -> Result<usize> {
    if let Some(index) = address_index(entries, target) {
        return Ok(index);
    }
    if let Some(o) = overlay {
        // The names are qualified and already carry the shift, so they name
        // the corpus address the method sits at.
        if let Some(addr) = o.by_name.get(target) {
            if let Some(index) = entries.iter().position(|entry| entry.address == *addr) {
                return Ok(index);
            }
        }
        for (name, addr) in &o.by_name {
            if name.contains(target) {
                if let Some(index) = entries.iter().position(|entry| entry.address == *addr) {
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

/// The index of the function at the address `target` names, when it names one.
///
/// The address may be written `0x1000`, `0X1000`, or as bare hexadecimal, and
/// it may name a space: `EXTERNAL:0x1` finds the function at `0x1` in the
/// `EXTERNAL` space, and the space match ignores case. A bare address finds
/// the function at that value whatever space it is in, the first one winning.
/// A target that names no function is not an error here: it may still be a
/// name, and the caller looks for one.
fn address_index(entries: &[Entry], target: &str) -> Option<usize> {
    let (address, space) = ag_corpus::parse_addr_space(target).ok()?;
    match space {
        Some(space) => entries.iter().position(|entry| {
            entry.address == address
                && entry
                    .space
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&space))
        }),
        None => entries.iter().position(|entry| entry.address == address),
    }
}

/// Shorten a string to at most `limit` characters.
///
/// The cut is made at a character boundary, so a name or a type holding
/// characters outside ASCII is never cut in half.
fn truncate_chars(text: &str, limit: usize) -> &str {
    match text.char_indices().nth(limit) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two functions, as a corpus or an export would report them.
    fn entries() -> Vec<Entry> {
        vec![
            Entry {
                address: 0x1000,
                space: None,
                name: "one".into(),
                status: "written".into(),
                range: None,
                has_body: true,
            },
            Entry {
                address: 0x2000,
                space: None,
                name: "two".into(),
                status: "written".into(),
                range: None,
                has_body: true,
            },
        ]
    }

    /// A function in the default space and one in a named space, sharing a value.
    fn spaced_entries() -> Vec<Entry> {
        vec![
            Entry {
                address: 0x1,
                space: None,
                name: "local".into(),
                status: "written".into(),
                range: None,
                has_body: true,
            },
            Entry {
                address: 0x1,
                space: Some("EXTERNAL".into()),
                name: "<EXTERNAL>::qsort".into(),
                status: "failed".into(),
                range: None,
                has_body: false,
            },
        ]
    }

    #[test]
    fn a_spaced_address_finds_the_function_in_that_space() {
        let entries = spaced_entries();

        assert_eq!(
            resolve(&entries, None, "EXTERNAL:0x1").expect("the external"),
            1,
            "the space names the second function"
        );
        assert_eq!(
            resolve(&entries, None, "external:0x1").expect("the external"),
            1,
            "the space match ignores case"
        );
        // A bare address names the value, and the first function wins.
        assert_eq!(resolve(&entries, None, "0x1").expect("a function"), 0);
    }

    #[test]
    fn a_spaced_address_is_displayed_with_its_space() {
        let entries = spaced_entries();
        assert_eq!(entries[0].display_address(), "0x1");
        assert_eq!(entries[1].display_address(), "EXTERNAL:0x1");
    }

    #[test]
    fn an_address_is_found_whatever_way_it_is_written() {
        let entries = entries();

        for target in ["0x1000", "0X1000", "1000"] {
            assert_eq!(
                resolve(&entries, None, target).expect("a function"),
                0,
                "{target} names the first function"
            );
        }
    }

    #[test]
    fn a_qualified_method_name_names_its_function() {
        use ag_corpus::objc::{MethodMap, ObjCMethod};

        let entries = entries();
        let map = MethodMap {
            methods: vec![
                ObjCMethod {
                    imp: 0x1000,
                    class: "Foo".into(),
                    sel: "bar".into(),
                    types: None,
                    is_class_method: false,
                },
                ObjCMethod {
                    imp: 0x2000,
                    class: "Foo".into(),
                    sel: "bar".into(),
                    types: None,
                    is_class_method: true,
                },
            ],
            warnings: Vec::new(),
        };
        let overlay = Overlay::new(map);

        assert_eq!(
            resolve(&entries, Some(&overlay), "-[Foo bar]").expect("a function"),
            0,
            "the instance method names the first function"
        );
        assert_eq!(
            resolve(&entries, Some(&overlay), "+[Foo bar]").expect("a function"),
            1,
            "the class method names the second function"
        );
    }

    #[test]
    fn an_address_that_names_no_function_falls_through_to_the_name() {
        let entries = entries();

        // The target reads as an address, but no function is there.
        let error = resolve(&entries, None, "0X9999").expect_err("no function");
        assert!(
            error.to_string().contains("no function matching"),
            "the lookup falls through to the name: {error}"
        );
    }

    #[test]
    fn a_name_that_reads_like_an_address_is_still_a_name() {
        let mut entries = entries();
        entries[0].name = "add".into();

        assert_eq!(
            resolve(&entries, None, "add").expect("a function"),
            0,
            "the name is found, not the address 0xadd"
        );
    }

    #[test]
    fn a_name_with_characters_outside_ascii_is_not_cut_in_half() {
        // The cut lands in the middle of the two-byte character.
        let text = format!("{}é", "n".repeat(69));

        let short = truncate_chars(&text, 70);
        assert_eq!(short.chars().count(), 70);
        assert!(short.ends_with('é'), "the character is whole: {short:?}");
    }

    #[test]
    fn a_short_name_is_left_alone() {
        assert_eq!(truncate_chars("short", 70), "short");
        assert_eq!(truncate_chars("", 70), "");
    }
}
