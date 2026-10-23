use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub mod kuna;
pub mod objc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyRange {
    Contiguous { start: u64, end: u64 },
    NonContiguous { ranges: Vec<(u64, u64)> },
}

#[derive(Debug, Clone)]
pub struct Function {
    pub address: u64,
    pub name: Option<String>,
    pub status: String,
    pub path: PathBuf,
    pub range: Option<BodyRange>,
}

impl Function {
    pub fn has_body(&self) -> bool {
        self.status == "written" && self.range.is_some()
    }
}

#[derive(Debug, Deserialize)]
pub struct BodyRangeJson {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Deserialize)]
pub struct BodyJson {
    available: bool,
    ranges: Vec<BodyRangeJson>,
    non_contiguous: bool,
}

#[derive(Debug, Deserialize)]
pub struct FunctionJson {
    pub address: String,
    pub name: String,
    pub status: String,
    #[serde(rename = "relative_path")]
    pub relative_path: Option<String>,
    pub body: BodyJson,
}

impl FunctionJson {
    /// The function this record describes.
    ///
    /// A record that does not describe a function — an address that is not an
    /// address, a range that cannot be read — is an error. The caller says so
    /// rather than dropping the record in silence.
    pub fn to_function(&self, corpus_root: &Path) -> Result<Function> {
        let address = parse_addr(&self.address)
            .with_context(|| format!("the address of {}", self.label()))?;

        let range = if self.body.available && !self.body.ranges.is_empty() {
            let parsed = self
                .body
                .ranges
                .iter()
                .map(|r| Ok((parse_addr(&r.start)?, parse_addr(&r.end)?)))
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("the body range of {}", self.label()))?;
            Some(if self.body.non_contiguous || parsed.len() > 1 {
                BodyRange::NonContiguous { ranges: parsed }
            } else {
                let (start, end) = parsed[0];
                BodyRange::Contiguous { start, end }
            })
        } else {
            None
        };

        let path = match &self.relative_path {
            Some(rp) => corpus_root.join(rp),
            None => corpus_root
                .join("functions")
                .join(format!("{:#x}.c", address)),
        };
        let name = if self.name.is_empty() {
            None
        } else {
            Some(self.name.clone())
        };

        Ok(Function {
            address,
            name,
            status: self.status.clone(),
            path,
            range,
        })
    }

    /// A name for this record, for a message about it.
    fn label(&self) -> String {
        if self.name.is_empty() {
            format!("the function at {}", self.address)
        } else {
            format!("{:?}", self.name)
        }
    }
}

/// Parse an address written as hexadecimal.
///
/// The prefix is optional and its case does not matter: `0x1000`, `0X1000`
/// and `1000` all name the same address. Anything that is not hexadecimal is
/// an error.
pub fn parse_addr(s: &str) -> Result<u64> {
    let trimmed = s.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if digits.is_empty() || !digits.chars().all(|digit| digit.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("non-address {s:?}"));
    }

    u64::from_str_radix(digits, 16).map_err(|_| anyhow::anyhow!("bad address {s:?}"))
}

#[derive(Debug, Deserialize)]
pub struct Index {
    pub version: u64,
    pub target_sha256: String,
    pub provider: Provider,
    pub functions: Vec<FunctionJson>,
}

#[derive(Debug, Deserialize)]
pub struct Provider {
    pub id: String,
    #[allow(dead_code)]
    pub name: String,
    pub version: String,
}

pub struct Corpus {
    pub root: PathBuf,
    pub target_sha256: String,
    pub provider: (String, String),
    pub functions: Vec<Function>,
    pub by_name: BTreeMap<String, Vec<usize>>,
    pub by_address: BTreeMap<u64, usize>,
    /// What the loader had to say about the data it read.
    ///
    /// A record that could not be read is skipped and named here; two
    /// records that claim the same address are both kept, the first one
    /// wins the address, and the clash is named here too. Nothing is
    /// dropped in silence.
    pub warnings: Vec<String>,
}

impl Corpus {
    pub fn load(root: &Path) -> Result<Corpus> {
        let index_path = root.join("decompile-index.json");
        let raw = fs::read_to_string(&index_path)
            .with_context(|| format!("reading {}", index_path.display()))?;
        let idx: Index = serde_json::from_str(&raw).context("parsing decompile-index.json")?;

        let mut functions = Vec::with_capacity(idx.functions.len());
        let mut warnings = Vec::new();

        for fj in &idx.functions {
            match fj.to_function(root) {
                Ok(f) => functions.push(f),
                Err(error) => warnings.push(format!("a record was skipped: {error:#}")),
            }
        }

        let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut by_address: BTreeMap<u64, usize> = BTreeMap::new();

        for (i, f) in functions.iter().enumerate() {
            if let Some(n) = &f.name {
                by_name.entry(n.clone()).or_default().push(i);
            }

            // Two records may claim the same address. Both are kept — a
            // second name for the same code is information — but the address
            // resolves to the first, and the clash is said out loud.
            match by_address.entry(f.address) {
                Entry::Vacant(slot) => {
                    slot.insert(i);
                }
                Entry::Occupied(slot) => {
                    let first = &functions[*slot.get()];
                    warnings.push(format!(
                        "two functions claim the address {:#x}: {} and {}; the address resolves to {}",
                        f.address,
                        first.name.as_deref().unwrap_or("(unnamed)"),
                        f.name.as_deref().unwrap_or("(unnamed)"),
                        first.name.as_deref().unwrap_or("(unnamed)")
                    ));
                }
            }
        }

        Ok(Corpus {
            root: root.to_path_buf(),
            target_sha256: idx.target_sha256,
            provider: (idx.provider.id.clone(), idx.provider.version.clone()),
            functions,
            by_name,
            by_address,
            warnings,
        })
    }

    pub fn function_body(&self, f: &Function) -> Result<String> {
        let raw =
            fs::read_to_string(&f.path).with_context(|| format!("reading {}", f.path.display()))?;
        Ok(Self::drop_header(&raw))
    }

    /// Drop the leading comment header of a function body.
    ///
    /// The header is the run of `//` comment lines at the top of the file —
    /// the lines the provider wrote to say which function this is. The body
    /// is everything after it, and the body keeps its signature and its
    /// locals: a header is dropped, not a function's head.
    pub fn drop_header(raw: &str) -> String {
        let mut body = String::new();
        let mut in_header = true;

        for line in raw.lines() {
            let trimmed = line.trim();

            if in_header {
                if trimmed.is_empty() || trimmed.starts_with("//") {
                    continue;
                }
                in_header = false;
            }

            body.push_str(line);
            body.push('\n');
        }

        body.trim_end().to_string()
    }
}

pub struct CorpusStats {
    pub total: usize,
    pub written: usize,
    pub failed: usize,
    pub external: usize,
    pub named_distinct: usize,
}

pub fn stats(corpus: &Corpus) -> CorpusStats {
    let external = corpus
        .functions
        .iter()
        .filter(|f| {
            f.name
                .as_deref()
                .is_none_or(|n| n.starts_with("<EXTERNAL>"))
        })
        .count();
    let written = corpus
        .functions
        .iter()
        .filter(|f| f.status == "written")
        .count();
    let failed = corpus
        .functions
        .iter()
        .filter(|f| f.status == "failed")
        .count();
    let named_distinct = corpus.by_name.len();
    CorpusStats {
        total: corpus.functions.len(),
        written,
        failed,
        external,
        named_distinct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// A temporary directory that cleans itself up.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!(
                "ag-corpus-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            fs::create_dir_all(&path).expect("a temporary directory");
            TempDir(path)
        }

        fn write(&self, name: &str, contents: &str) {
            let mut file = fs::File::create(self.0.join(name)).expect("a file");
            file.write_all(contents.as_bytes()).expect("contents");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A corpus index holding the given function records.
    fn index_with(records: &str) -> String {
        format!(
            concat!(
                "{{\"version\":1,\"target_sha256\":\"9f86d0\",\"provider\":",
                "{{\"id\":\"ag-engine\",\"name\":\"AdmiralGrace\",\"version\":\"0.1.0\"}},",
                "\"functions\":[{records}]}}\n"
            ),
            records = records
        )
    }

    /// A function record with no body.
    fn record(address: &str, name: &str) -> String {
        format!(
            concat!(
                "{{\"address\":\"{}\",\"name\":\"{}\",\"status\":\"written\",",
                "\"body\":{{\"available\":false,\"non_contiguous\":false,\"ranges\":[]}}}}"
            ),
            address, name
        )
    }

    #[test]
    fn an_address_is_read_with_or_without_its_prefix() {
        assert_eq!(parse_addr("0x1000").expect("an address"), 0x1000);
        assert_eq!(parse_addr("0X1000").expect("an address"), 0x1000);
        assert_eq!(parse_addr("1000").expect("an address"), 0x1000);
        assert_eq!(parse_addr("0xdeadbeef").expect("an address"), 0xdeadbeef);
        assert_eq!(parse_addr(" 0x1000 ").expect("an address"), 0x1000);
    }

    #[test]
    fn a_non_address_is_refused() {
        for text in ["", "0x", "0X", "zzz", "0x1000h", "0x 1000", "-1"] {
            assert!(parse_addr(text).is_err(), "{text:?} is not an address");
        }
    }

    #[test]
    fn a_header_is_dropped_and_the_body_is_kept() {
        // The header is the run of comment lines at the top. Everything from
        // the signature on is the body, and none of it is lost.
        let raw = concat!(
            "// Function: one @ 0x1000\n",
            "// Written by the provider\n",
            "\n",
            "int one(int a)\n",
            "{\n",
            "  int b = a + 1;\n",
            "\n",
            "  return b;\n",
            "}\n",
        );

        let body = Corpus::drop_header(raw);

        assert!(
            !body.contains("Function: one"),
            "the header is gone: {body:?}"
        );
        assert!(
            body.contains("int one(int a)"),
            "the signature is kept: {body:?}"
        );
        assert!(
            body.contains("int b = a + 1;"),
            "the locals are kept: {body:?}"
        );
        assert!(body.contains("return b;"), "the rest is kept: {body:?}");
    }

    #[test]
    fn a_record_that_cannot_be_read_is_skipped_and_said() {
        let dir = TempDir::new("bad-record");
        dir.write(
            "decompile-index.json",
            &index_with(&format!(
                "{},{}",
                record("not-an-address", "broken"),
                record("0x1000", "good")
            )),
        );

        let corpus = Corpus::load(&dir.0).expect("a corpus");

        assert_eq!(
            corpus.functions.len(),
            1,
            "the broken record is not kept: {:?}",
            corpus.functions
        );
        assert_eq!(corpus.functions[0].name.as_deref(), Some("good"));
        assert!(
            corpus.by_address.contains_key(&0x1000),
            "the good record is still found"
        );
        assert_eq!(
            corpus.warnings.len(),
            1,
            "the break is said: {:?}",
            corpus.warnings
        );
        assert!(
            corpus.warnings[0].contains("skipped"),
            "the warning says what happened: {:?}",
            corpus.warnings
        );
        assert!(
            corpus.warnings[0].contains("not-an-address"),
            "the warning names the record: {:?}",
            corpus.warnings
        );
    }

    #[test]
    fn two_records_at_one_address_are_both_kept_and_the_clash_is_said() {
        let dir = TempDir::new("dup-address");
        dir.write(
            "decompile-index.json",
            &index_with(&format!(
                "{},{}",
                record("0x1000", "one"),
                record("0x1000", "two")
            )),
        );

        let corpus = Corpus::load(&dir.0).expect("a corpus");

        assert_eq!(
            corpus.functions.len(),
            2,
            "both records are kept: {:?}",
            corpus.functions
        );
        assert_eq!(
            corpus.by_address.get(&0x1000).copied(),
            Some(0),
            "the address resolves to the first"
        );
        assert_eq!(
            corpus.warnings.len(),
            1,
            "the clash is said: {:?}",
            corpus.warnings
        );
        assert!(
            corpus.warnings[0].contains("0x1000"),
            "the warning names the address: {:?}",
            corpus.warnings
        );
        assert!(
            corpus.warnings[0].contains("one") && corpus.warnings[0].contains("two"),
            "the warning names both records: {:?}",
            corpus.warnings
        );
    }
}
