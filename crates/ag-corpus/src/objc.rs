use anyhow::Result;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct ObjCMethodRecord {
    pub imp: String,
    pub class: Option<String>,
    pub sel: String,
    pub types: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObjCMethod {
    pub imp: u64,
    pub class: String,
    pub sel: String,
    pub types: Option<String>,
}

pub fn load_map(path: &Path) -> Result<Vec<ObjCMethod>> {
    let raw = fs::read_to_string(path)?;
    let recs: Vec<ObjCMethodRecord> = serde_json::from_str(&raw)?;
    Ok(recs
        .into_iter()
        .map(|r| ObjCMethod {
            imp: crimp_parse_addr(&r.imp),
            class: r.class.unwrap_or_default(),
            sel: r.sel,
            types: r.types,
        })
        .collect())
}

fn crimp_parse_addr(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
}

pub fn method_display(m: &ObjCMethod) -> String {
    format!("-[{} {}]", m.class, m.sel)
}

pub struct Overlay {
    pub shift: u64,
    pub by_imp: BTreeMap<u64, ObjCMethod>,
    pub by_name: BTreeMap<String, u64>,
}

impl Overlay {
    pub fn new(methods: Vec<ObjCMethod>) -> Overlay {
        let mut by_imp = BTreeMap::new();
        let mut by_name = BTreeMap::new();
        for m in methods {
            let n = method_display(&m);
            by_name.insert(n, m.imp);
            by_imp.insert(m.imp, m);
        }
        Overlay {
            shift: 0,
            by_imp,
            by_name,
        }
    }

    /// Set the image-base shift: corpus addresses are `imp + shift`.
    pub fn with_shift(mut self, shift: u64) -> Overlay {
        self.shift = shift;
        by_imp_with_shift(&mut self.by_imp, shift);
        self
    }

    pub fn imp_addr(&self, imp: u64) -> u64 {
        imp + self.shift
    }
}

fn by_imp_with_shift(map: &mut BTreeMap<u64, ObjCMethod>, shift: u64) {
    let old = std::mem::take(map);
    let entries: BTreeMap<u64, ObjCMethod> = old
        .into_iter()
        .map(|(k, v)| (k.wrapping_add(shift), v))
        .collect();
    *map = entries;
}
