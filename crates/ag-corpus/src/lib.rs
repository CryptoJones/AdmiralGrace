use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

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
    pub source: Sha256,
}

#[derive(Debug, Clone)]
pub struct Sha256(pub String);

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
    pub fn to_function(&self, corpus_root: &Path) -> Result<Option<Function>> {
        let address = match parse_addr(&self.address) {
            Ok(a) => a,
            Err(_) => return Ok(None),
        };
        let range = if self.body.available && !self.body.ranges.is_empty() {
            let parsed = self
                .body
                .ranges
                .iter()
                .map(|r| Ok((parse_addr(&r.start)?, parse_addr(&r.end)?)))
                .collect::<Result<Vec<_>>>()?;
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
            None => corpus_root.join("functions").join(format!("{:#x}.c", address)),
        };
        let name = if self.name.is_empty() {
            None
        } else {
            Some(self.name.clone())
        };
        Ok(Some(Function {
            address,
            name,
            status: self.status.clone(),
            path,
            range,
            source: Sha256(String::new()),
        }))
    }
}

pub fn parse_addr(s: &str) -> Result<u64> {
    let h = s
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("non-address {s:?}"))?;
    u64::from_str_radix(h, 16).map_err(|_| anyhow::anyhow!("bad address {s:?}"))
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
}

impl Corpus {
    pub fn load(root: &Path) -> Result<Corpus> {
        let index_path = root.join("decompile-index.json");
        let raw = fs::read_to_string(&index_path)
            .with_context(|| format!("reading {}", index_path.display()))?;
        let idx: Index =
            serde_json::from_str(&raw).context("parsing decompile-index.json")?;
        let mut functions = Vec::with_capacity(idx.functions.len());
        for fj in &idx.functions {
            let f = match fj.to_function(root) {
                Ok(Some(f)) => f,
                _ => continue,
            };
            functions.push(f);
        }
        let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut by_address: BTreeMap<u64, usize> = BTreeMap::new();
        for (i, f) in functions.iter().enumerate() {
            if let Some(n) = &f.name {
                by_name.entry(n.clone()).or_default().push(i);
            }
            by_address.entry(f.address).or_insert(i);
        }
        Ok(Corpus {
            root: root.to_path_buf(),
            target_sha256: idx.target_sha256,
            provider: (idx.provider.id.clone(), idx.provider.version.clone()),
            functions,
            by_name,
            by_address,
        })
    }

    pub fn function_body(&self, f: &Function) -> Result<String> {
        let raw = fs::read_to_string(&f.path)
            .with_context(|| format!("reading {}", f.path.display()))?;
        Ok(Self::drop_header(&raw))
    }

    /// Drop the leading `// ...` comment header.
    pub fn drop_header(raw: &str) -> String {
        let body = raw.trim().to_string();
        if let Some(idx) = body.find("\n\n") {
            let head = &body[..idx];
            if head.trim_start().starts_with("//") {
                return body[idx + 2..].to_string();
            }
        }
        body
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
        .filter(|f| f.name.as_deref().map_or(true, |n| n.starts_with("<EXTERNAL>")))
        .count();
    let written = corpus.functions.iter().filter(|f| f.status == "written").count();
    let failed = corpus.functions.iter().filter(|f| f.status == "failed").count();
    let named_distinct = corpus.by_name.len();
    CorpusStats {
        total: corpus.functions.len(),
        written,
        failed,
        external,
        named_distinct,
    }
}
