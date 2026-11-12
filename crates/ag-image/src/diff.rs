//! Reading a program image as the facts a version comparison matches on
//! (#398).
//!
//! The engine's [`diff`](ag_engine::diff) compares plain facts — a
//! function's whole-function hash, its byte length, the shape of its graph
//! and its mnemonics — so it can match any two versions without knowing
//! how they were read. This module reads those facts off a [`Binary`]:
//! every function's body, from its entry to where it ends, hashed under
//! the image's architecture the way [`funcid`](ag_engine::funcid) reads
//! it, and its disassembly counted into blocks, edges, instructions and
//! calls. `ag diff` and the workbench's comparison both read the same
//! facts, so both draw the same matches.

use std::collections::BTreeMap;

use crate::Binary;

pub use ag_engine::diff::{
    diff, similarity, DiffOptions, DiffReport, FunctionFacts, FunctionMatch, FunctionRef, MatchKind,
    MIN_SIMILARITY,
};
use ag_engine::funcid;

/// The function's real name, when it has one: a name the analysis made up
/// (`sub_…`, `nullsub_…`, `loc_…`, `unknown_…`) names nothing to match on,
/// so it reads as `None`.
pub fn real_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty()
        || name.starts_with("sub_")
        || name.starts_with("nullsub_")
        || name.starts_with("loc_")
        || name.starts_with("unknown_")
    {
        return None;
    }
    Some(name.to_string())
}

/// The facts of every function of the image, in address order: its
/// whole-function hash, its byte length, and the shape and mnemonics of
/// its disassembly. A function runs to where the unwind data says it ends,
/// or to the next function, or to the end of its section — the same extent
/// the listing and the signature fingerprints read. A function whose bytes
/// cannot be read is left out; one whose disassembly cannot be read carries
/// its hash alone, so it can still match by hash or by name.
pub fn facts_of(binary: &Binary) -> Vec<FunctionFacts> {
    let arch = funcid::arch_of_language(binary.language());
    let mut functions: Vec<&crate::Function> = binary.functions().iter().collect();
    functions.sort_by_key(|f| f.address);
    functions.dedup_by_key(|f| f.address);
    let mut out = Vec::new();
    for (index, function) in functions.iter().enumerate() {
        let next = functions.get(index + 1).map(|f| f.address);
        let mut end = binary.function_end(function.address).unwrap_or(u64::MAX);
        if let Some(next) = next {
            end = end.min(next);
        }
        if let Some(section) = binary.section_of(function.address) {
            end = end.min(section.vma.saturating_add(section.size));
        }
        let length = end.saturating_sub(function.address) as usize;
        if length == 0 {
            continue;
        }
        let Some(bytes) = binary.bytes_at(function.address, length) else {
            continue;
        };
        let hash = funcid::function_hash(&arch, &bytes, function.address);
        let mut blocks = 0u32;
        let mut edges = 0u32;
        let mut instructions = 0u32;
        let mut calls = 0u32;
        let mut mnemonics = Vec::new();
        if let Some(disasm) = binary.disassembly(function.address) {
            blocks = disasm.blocks.len() as u32;
            for block in &disasm.blocks {
                edges += block.successors.len() as u32;
                instructions += block.instructions.len() as u32;
                mnemonics.extend(block.instructions.iter().map(|i| i.mnemonic.clone()));
            }
            calls = disasm.calls.len() as u32;
        }
        out.push(FunctionFacts {
            address: function.address,
            name: real_name(&function.name),
            hash,
            length: length as u64,
            blocks,
            edges,
            instructions,
            calls,
            mnemonics,
        });
    }
    out
}

/// Read the analyst's renames over the facts' names: a rename recorded for
/// a function is its name for the comparison, over the image's own. The
/// map keys each renamed function's entry address.
pub fn rename_facts(facts: &mut [FunctionFacts], renamed: &BTreeMap<u64, String>) {
    for fact in facts.iter_mut() {
        if let Some(name) = renamed.get(&fact.address) {
            fact.name = Some(name.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-engine/tests/fixtures/sample.elf")
    }

    #[test]
    fn the_facts_carry_the_hash_the_signature_reads() {
        let binary = Binary::open(&sample_path()).expect("the sample opens");
        let facts = facts_of(&binary);
        assert!(!facts.is_empty(), "the sample has functions");
        // The facts are in address order, one a function, each with a
        // whole-function hash and a body the disassembly read.
        let mut sorted = facts.clone();
        sorted.sort_by_key(|f| f.address);
        assert_eq!(sorted, facts);
        let main = facts
            .iter()
            .find(|f| f.name.as_deref() == Some("main"))
            .expect("the sample names main");
        assert_eq!(main.hash.len(), 64);
        assert!(main.length > 0);
        assert!(main.instructions > 0);
        assert!(!main.mnemonics.is_empty());
        // The hash is the one the signature fingerprint reads over the
        // same extent.
        let arch = funcid::arch_of_language(binary.language());
        let bytes = binary
            .bytes_at(main.address, main.length as usize)
            .expect("main's bytes");
        assert_eq!(
            main.hash,
            funcid::function_hash(&arch, &bytes, main.address)
        );
    }

    #[test]
    fn a_placeholder_name_is_no_name() {
        assert_eq!(real_name("main"), Some("main".to_string()));
        assert_eq!(real_name("sub_1234"), None);
        assert_eq!(real_name("nullsub_7"), None);
        assert_eq!(real_name("loc_40"), None);
        assert_eq!(real_name("unknown_1"), None);
        assert_eq!(real_name("  "), None);
    }

    #[test]
    fn an_image_compared_with_itself_is_wholly_alike() {
        let binary = Binary::open(&sample_path()).expect("the sample opens");
        let facts = facts_of(&binary);
        let report = diff(&facts, &facts, &DiffOptions::default());
        assert_eq!(report.matched.len(), facts.len());
        assert!(report.removed.is_empty());
        assert!(report.added.is_empty());
        assert_eq!(report.similarity, 1.0);
        for pair in &report.matched {
            assert_eq!(pair.kind, MatchKind::Hash);
            assert_eq!(pair.similarity, 1.0);
        }
    }

    #[test]
    fn a_rename_is_the_name_the_comparison_reads() {
        let binary = Binary::open(&sample_path()).expect("the sample opens");
        let mut facts = facts_of(&binary);
        let main = facts
            .iter()
            .find(|f| f.name.as_deref() == Some("main"))
            .expect("the sample names main")
            .address;
        let mut renamed = BTreeMap::new();
        renamed.insert(main, "entry_point".to_string());
        rename_facts(&mut facts, &renamed);
        let fact = facts.iter().find(|f| f.address == main).expect("main");
        assert_eq!(fact.name.as_deref(), Some("entry_point"));
    }
}
