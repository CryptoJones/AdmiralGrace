//! Binary similarity and diffing between versions (#398).
//!
//! Comparing two builds of a program is how a patch is read: what stayed
//! the same, what changed, what arrived and what left. This module matches
//! the functions of one version against the other and scores each pair, so
//! an analyst can review the matches, carry names and types across them,
//! and see the comparison.
//!
//! # The facts a comparison reads
//!
//! A function is compared by what it is, not where it sits: a
//! [`FunctionFacts`] holds its whole-function hash ([`crate::funcid`]), its
//! byte length, the shape of its control-flow graph — basic blocks, edges,
//! instructions, calls — and its instruction mnemonics in order. The
//! addresses are carried for the report only; nothing in the matching
//! depends on them, so two builds loaded at different bases compare the
//! same.
//!
//! # The matching, in three passes
//!
//! 1. **Hash** — the same whole-function hash on both sides is the same
//!    code, byte for byte after the address-dependent operands are masked.
//!    A hash match scores 1.0. Where several functions share a hash — a
//!    thunk and its target — the pair that agrees on a name is taken first.
//! 2. **Name** — a real name both sides spell is the same function, however
//!    its code changed; the score says how much. A name the analysis made
//!    up (`sub_…`) names nothing and is not matched on.
//! 3. **Structure** — what is left is matched by shape: the mnemonics it
//!    executes, the graph it builds, the size it takes. Candidate pairs
//!    whose lengths or instruction counts differ by more than half are not
//!    considered — a function twice the size of another is not its next
//!    version — and the rest are scored, best first, each function taking
//!    at most one partner.
//!
//! # The score
//!
//! [`similarity`] weighs three readings of a pair, each between 0 and 1:
//! the cosine of the mnemonic histograms (what the code does), the mean
//! ratio of the graph counts (the shape it takes), and the ratio of the
//! byte lengths (the room it fills). Identical facts score 1.0; a pair
//! that shares nothing scores 0. The whole-image similarity is the Dice
//! coefficient of the match: twice the matched count over the sum of the
//! two function counts, 1.0 when both sides are empty.
//!
//! The facts are plain data, so the engine compares anything that can
//! produce them; `ag_image::Binary::diff_facts` reads them off a program
//! image, and `ag diff` reports the comparison. See `docs/diff.md`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The lowest similarity a structural match is drawn at. A name or a hash
/// is believed however the code changed; a shape alone must say this much
/// to be a match.
pub const MIN_SIMILARITY: f64 = 0.6;

/// The smallest ratio of lengths or instruction counts a structural
/// candidate pair may have: a function less than half the size of another
/// is not considered its next version.
const SIZE_FLOOR: f64 = 0.5;

/// One function, as a comparison reads it: the fingerprint of its body,
/// the shape of its graph, and the mnemonics it executes. The address and
/// the name are carried for the report; the matching reads the rest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionFacts {
    /// The function's entry address in its own image.
    pub address: u64,
    /// The function's real name — the symbol's, or the analyst's rename —
    /// when it has one. A placeholder the analysis made up (`sub_…`) is
    /// `None`: it names nothing to match on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The whole-function hash, as [`crate::funcid::function_hash`] writes
    /// it: the same code at any load address hashes the same.
    pub hash: String,
    /// The function's length in bytes.
    pub length: u64,
    /// How many basic blocks its control-flow graph holds.
    pub blocks: u32,
    /// How many edges its control-flow graph holds.
    pub edges: u32,
    /// How many instructions its body holds.
    pub instructions: u32,
    /// How many calls it makes — direct calls and tail calls.
    pub calls: u32,
    /// The mnemonics of its instructions, as the disassembler spells them;
    /// the comparison reads their counts, not their order.
    pub mnemonics: Vec<String>,
}

/// What drew a match: the evidence the pair stands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    /// The whole-function hashes are equal: the same code, byte for byte
    /// after the address-dependent operands are masked.
    Hash,
    /// Both sides spell the same real name.
    Name,
    /// The shapes are alike enough: mnemonics, graph and size.
    Structure,
}

impl MatchKind {
    /// The kind as a report spells it.
    pub fn label(self) -> &'static str {
        match self {
            MatchKind::Hash => "hash",
            MatchKind::Name => "name",
            MatchKind::Structure => "structure",
        }
    }
}

/// One function of a comparison, as the report names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRef {
    /// The function's entry address in its own image.
    pub address: u64,
    /// The function's real name, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// One matched pair of functions and the evidence and score of the match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionMatch {
    /// The older version's function.
    pub old: FunctionRef,
    /// The newer version's function.
    pub new: FunctionRef,
    /// How alike the pair is, between 0 and 1; a hash match is 1.0.
    pub similarity: f64,
    /// What drew the match.
    pub kind: MatchKind,
}

impl FunctionMatch {
    /// Whether the pair's code differs: a hash match is the same code, so
    /// every other match — a name's, a shape's — carries a change.
    pub fn changed(&self) -> bool {
        self.kind != MatchKind::Hash
    }
}

/// The comparison of two versions: the matched pairs, the functions only
/// one side holds, and the whole-image similarity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffReport {
    /// The matched pairs, in the older version's address order.
    pub matched: Vec<FunctionMatch>,
    /// The older version's functions the newer one does not hold, in
    /// address order — what left.
    pub removed: Vec<FunctionRef>,
    /// The newer version's functions the older one does not hold, in
    /// address order — what arrived.
    pub added: Vec<FunctionRef>,
    /// The whole-image similarity: twice the matched count over the sum
    /// of the two function counts, 1.0 when both sides are empty.
    pub similarity: f64,
}

/// What a comparison is drawn under.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffOptions {
    /// The lowest similarity a structural match is drawn at; a name or a
    /// hash is believed however the code changed. [`MIN_SIMILARITY`] by
    /// default.
    pub min_similarity: f64,
}

impl Default for DiffOptions {
    fn default() -> Self {
        DiffOptions {
            min_similarity: MIN_SIMILARITY,
        }
    }
}

/// The ratio of two counts, between 0 and 1: the smaller over the larger,
/// and 1.0 when both are zero — two empty things are alike.
fn ratio(a: u64, b: u64) -> f64 {
    if a == 0 && b == 0 {
        return 1.0;
    }
    a.min(b) as f64 / a.max(b) as f64
}

/// The cosine of two mnemonic histograms: the dot of the counts over the
/// product of their lengths, 1.0 when both are empty and 0.0 when only one
/// is. The histograms are built once a function, so a pair's reading is a
/// walk of the smaller.
fn cosine(a: &BTreeMap<&str, u32>, b: &BTreeMap<&str, u32>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let dot: u64 = small
        .iter()
        .map(|(word, count)| u64::from(*count) * u64::from(large.get(word).copied().unwrap_or(0)))
        .sum();
    if dot == 0 {
        return 0.0;
    }
    let square = |hist: &BTreeMap<&str, u32>| -> u64 {
        hist.values()
            .map(|count| u64::from(*count) * u64::from(*count))
            .sum()
    };
    let (sq_a, sq_b) = (square(a), square(b));
    // A pair whose dot equals both squares is the same histogram: alike
    // exactly, without a rounding's worth of doubt.
    if u128::from(dot) * u128::from(dot) == u128::from(sq_a) * u128::from(sq_b) {
        return 1.0;
    }
    (dot as f64) / ((sq_a as f64).sqrt() * (sq_b as f64).sqrt())
}

/// How alike two functions are, between 0 and 1: the cosine of their
/// mnemonic histograms (what the code does), the mean ratio of their graph
/// counts — blocks, edges, instructions (the shape it takes) — and the
/// ratio of their byte lengths (the room it fills), weighed half, three
/// tenths and two tenths. Identical facts score 1.0.
pub fn similarity(a: &FunctionFacts, b: &FunctionFacts) -> f64 {
    let hist_a = histogram(&a.mnemonics);
    let hist_b = histogram(&b.mnemonics);
    similarity_hist(a, b, &hist_a, &hist_b)
}

/// [`similarity`] with the histograms already built, for a comparison that
/// scores many pairs.
fn similarity_hist(
    a: &FunctionFacts,
    b: &FunctionFacts,
    hist_a: &BTreeMap<&str, u32>,
    hist_b: &BTreeMap<&str, u32>,
) -> f64 {
    let code = cosine(hist_a, hist_b);
    let shape = (ratio(u64::from(a.blocks), u64::from(b.blocks))
        + ratio(u64::from(a.edges), u64::from(b.edges))
        + ratio(u64::from(a.instructions), u64::from(b.instructions)))
        / 3.0;
    let size = ratio(a.length, b.length);
    0.5 * code + 0.3 * shape + 0.2 * size
}

/// The counts of each mnemonic in a body.
fn histogram(mnemonics: &[String]) -> BTreeMap<&str, u32> {
    let mut hist = BTreeMap::new();
    for word in mnemonics {
        *hist.entry(word.as_str()).or_insert(0) += 1;
    }
    hist
}

/// A function as the matching holds it: its facts, its mnemonic histogram,
/// and whether a pass has taken it.
struct Candidate<'a> {
    facts: &'a FunctionFacts,
    hist: BTreeMap<&'a str, u32>,
    taken: bool,
}

impl<'a> Candidate<'a> {
    fn new(facts: &'a FunctionFacts) -> Candidate<'a> {
        Candidate {
            facts,
            hist: histogram(&facts.mnemonics),
            taken: false,
        }
    }

    fn reference(&self) -> FunctionRef {
        FunctionRef {
            address: self.facts.address,
            name: self.facts.name.clone(),
        }
    }
}

/// Compare two versions' functions: match them by hash, then by name, then
/// by shape, and report the pairs, what only one side holds, and the
/// whole-image similarity. The facts of each side are read in address
/// order, one a function.
pub fn diff(old: &[FunctionFacts], new: &[FunctionFacts], options: &DiffOptions) -> DiffReport {
    let mut olds: Vec<Candidate> = old.iter().map(Candidate::new).collect();
    let mut news: Vec<Candidate> = new.iter().map(Candidate::new).collect();
    let mut matched: Vec<FunctionMatch> = Vec::new();

    // Pass one: the same whole-function hash is the same code. Where
    // several functions share a hash, the pair that agrees on a name is
    // taken first, then the first free partner in address order.
    let mut by_hash: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, candidate) in news.iter().enumerate() {
        by_hash
            .entry(candidate.facts.hash.as_str())
            .or_default()
            .push(index);
    }
    for older in olds.iter_mut() {
        let Some(partners) = by_hash.get(older.facts.hash.as_str()) else {
            continue;
        };
        let free = partners.iter().copied().filter(|&i| !news[i].taken);
        let chosen = free
            .clone()
            .find(|&i| news[i].facts.name.is_some() && news[i].facts.name == older.facts.name)
            .or_else(|| free.into_iter().next());
        if let Some(index) = chosen {
            news[index].taken = true;
            older.taken = true;
            matched.push(FunctionMatch {
                old: older.reference(),
                new: news[index].reference(),
                similarity: 1.0,
                kind: MatchKind::Hash,
            });
        }
    }

    // Pass two: a real name both sides spell is the same function, however
    // its code changed. The best-scoring free carrier of the name is taken.
    let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, candidate) in news.iter().enumerate() {
        if candidate.taken {
            continue;
        }
        if let Some(name) = candidate.facts.name.as_deref() {
            by_name.entry(name).or_default().push(index);
        }
    }
    for older in olds.iter_mut() {
        if older.taken {
            continue;
        }
        let Some(name) = older.facts.name.as_deref() else {
            continue;
        };
        let Some(partners) = by_name.get(name) else {
            continue;
        };
        let chosen = partners
            .iter()
            .copied()
            .filter(|&i| !news[i].taken)
            .max_by(|&a, &b| {
                let score_a = similarity_hist(older.facts, news[a].facts, &older.hist, &news[a].hist);
                let score_b = similarity_hist(older.facts, news[b].facts, &older.hist, &news[b].hist);
                score_a
                    .total_cmp(&score_b)
                    .then_with(|| news[b].facts.address.cmp(&news[a].facts.address))
            });
        if let Some(index) = chosen {
            let score = similarity_hist(older.facts, news[index].facts, &older.hist, &news[index].hist);
            news[index].taken = true;
            older.taken = true;
            matched.push(FunctionMatch {
                old: older.reference(),
                new: news[index].reference(),
                similarity: score,
                kind: MatchKind::Name,
            });
        }
    }

    // Pass three: what is left is matched by shape. Candidate pairs whose
    // lengths or instruction counts differ by more than half are not
    // considered; the rest are scored, best first, each function taking at
    // most one partner.
    let mut scored: Vec<(f64, usize, usize)> = Vec::new();
    for (oi, older) in olds.iter().enumerate() {
        if older.taken {
            continue;
        }
        for (ni, newer) in news.iter().enumerate() {
            if newer.taken {
                continue;
            }
            if ratio(older.facts.length, newer.facts.length) < SIZE_FLOOR
                || ratio(
                    u64::from(older.facts.instructions),
                    u64::from(newer.facts.instructions),
                ) < SIZE_FLOOR
            {
                continue;
            }
            let score = similarity_hist(older.facts, newer.facts, &older.hist, &newer.hist);
            if score >= options.min_similarity {
                scored.push((score, oi, ni));
            }
        }
    }
    scored.sort_by(|a, b| {
        b.0.total_cmp(&a.0)
            .then_with(|| olds[a.1].facts.address.cmp(&olds[b.1].facts.address))
            .then_with(|| news[a.2].facts.address.cmp(&news[b.2].facts.address))
    });
    for (score, oi, ni) in scored {
        if olds[oi].taken || news[ni].taken {
            continue;
        }
        olds[oi].taken = true;
        news[ni].taken = true;
        matched.push(FunctionMatch {
            old: olds[oi].reference(),
            new: news[ni].reference(),
            similarity: score,
            kind: MatchKind::Structure,
        });
    }

    matched.sort_by_key(|pair| pair.old.address);
    let removed = olds
        .iter()
        .filter(|candidate| !candidate.taken)
        .map(Candidate::reference)
        .collect();
    let added = news
        .iter()
        .filter(|candidate| !candidate.taken)
        .map(Candidate::reference)
        .collect();
    let similarity = if old.is_empty() && new.is_empty() {
        1.0
    } else {
        2.0 * matched.len() as f64 / (old.len() + new.len()) as f64
    };
    DiffReport {
        matched,
        removed,
        added,
        similarity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Facts of a function, with the mnemonics spelled as a body's words.
    fn facts(address: u64, name: Option<&str>, hash: &str, mnemonics: &str) -> FunctionFacts {
        let words: Vec<String> = mnemonics.split_whitespace().map(str::to_string).collect();
        FunctionFacts {
            address,
            name: name.map(str::to_string),
            hash: hash.to_string(),
            length: words.len() as u64 * 4,
            blocks: 1,
            edges: 0,
            instructions: words.len() as u32,
            calls: 0,
            mnemonics: words,
        }
    }

    #[test]
    fn identical_functions_match_by_hash_at_any_address() {
        let old = vec![facts(0x1000, Some("init"), "aaa", "push mov call ret")];
        let new = vec![facts(0x9000, Some("init"), "aaa", "push mov call ret")];
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 1);
        let pair = &report.matched[0];
        assert_eq!(pair.old.address, 0x1000);
        assert_eq!(pair.new.address, 0x9000);
        assert_eq!(pair.kind, MatchKind::Hash);
        assert_eq!(pair.similarity, 1.0);
        assert!(!pair.changed());
        assert!(report.removed.is_empty());
        assert!(report.added.is_empty());
        assert_eq!(report.similarity, 1.0);
    }

    #[test]
    fn a_hash_match_needs_no_name() {
        let old = vec![facts(0x1000, None, "aaa", "xor ret")];
        let new = vec![facts(0x2000, None, "aaa", "xor ret")];
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 1);
        assert_eq!(report.matched[0].kind, MatchKind::Hash);
    }

    #[test]
    fn a_shared_hash_takes_the_name_agreeing_pair_first() {
        // A thunk and its target share a body; the new version spells both
        // names too. The pair that agrees on a name is taken first.
        let old = vec![
            facts(0x1000, Some("target"), "aaa", "xor ret"),
            facts(0x2000, Some("thunk"), "aaa", "xor ret"),
        ];
        let new = vec![
            facts(0x5000, Some("thunk"), "aaa", "xor ret"),
            facts(0x6000, Some("target"), "aaa", "xor ret"),
        ];
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 2);
        for pair in &report.matched {
            assert_eq!(pair.old.name, pair.new.name);
        }
    }

    #[test]
    fn a_renamed_function_still_matches_by_hash() {
        let old = vec![facts(0x1000, Some("old_name"), "aaa", "push mov ret")];
        let new = vec![facts(0x1000, Some("new_name"), "aaa", "push mov ret")];
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 1);
        assert_eq!(report.matched[0].kind, MatchKind::Hash);
    }

    #[test]
    fn the_same_name_matches_however_the_code_changed() {
        let old = vec![facts(0x1000, Some("parse"), "aaa", "push mov call ret")];
        let new = vec![facts(
            0x1000,
            Some("parse"),
            "bbb",
            "push sub mov mov cmp jne call add ret",
        )];
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 1);
        let pair = &report.matched[0];
        assert_eq!(pair.kind, MatchKind::Name);
        assert!(pair.changed());
        assert!(pair.similarity < 1.0);
        assert!(pair.similarity > 0.0);
    }

    #[test]
    fn a_placeholder_name_is_not_matched_on() {
        // `sub_…` names nothing: two functions the analysis made names for
        // match by shape only when their shapes agree.
        let old = vec![facts(0x1000, None, "aaa", "push mov ret")];
        let new = vec![facts(0x2000, None, "bbb", "push mov ret")];
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 1);
        assert_eq!(report.matched[0].kind, MatchKind::Structure);
    }

    #[test]
    fn changed_code_without_a_name_matches_by_shape() {
        // The same function after a patch: a few instructions added, the
        // hash gone, no name to hold it. The shape still draws the match.
        let old = vec![facts(
            0x1000,
            None,
            "aaa",
            "push mov mov cmp jle call mov pop ret",
        )];
        let new = vec![facts(
            0x3000,
            None,
            "bbb",
            "push mov mov test cmp jle call mov mov pop ret",
        )];
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 1);
        let pair = &report.matched[0];
        assert_eq!(pair.kind, MatchKind::Structure);
        assert!(pair.similarity >= MIN_SIMILARITY);
        assert!(pair.similarity < 1.0);
    }

    #[test]
    fn different_functions_do_not_match() {
        let old = vec![facts(0x1000, None, "aaa", "push mov call ret")];
        let new = vec![facts(
            0x2000,
            None,
            "bbb",
            "xor eax eax div ecx mul edx shl rax cl ret",
        )];
        let report = diff(&old, &new, &DiffOptions::default());
        assert!(report.matched.is_empty());
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.similarity, 0.0);
    }

    #[test]
    fn a_function_twice_the_size_is_not_a_structural_candidate() {
        // Same mnemonics repeated: the shapes read alike, but the length
        // ratio is under the floor, so no pair is considered.
        let old = vec![facts(0x1000, None, "aaa", "mov add ret")];
        let new = vec![facts(
            0x2000,
            None,
            "bbb",
            "mov add mov add mov add mov add ret",
        )];
        let report = diff(&old, &new, &DiffOptions::default());
        assert!(report.matched.is_empty());
    }

    #[test]
    fn each_function_takes_at_most_one_partner() {
        // Two identical old functions, one new: one matches, one leaves.
        let old = vec![
            facts(0x1000, None, "aaa", "xor ret"),
            facts(0x2000, None, "aaa", "xor ret"),
        ];
        let new = vec![facts(0x5000, None, "aaa", "xor ret")];
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 1);
        assert_eq!(report.matched[0].old.address, 0x1000);
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.removed[0].address, 0x2000);
        assert!(report.added.is_empty());
    }

    #[test]
    fn the_best_shape_wins_a_contested_match() {
        // One old function, two new candidates: the closer shape takes it.
        let old = vec![facts(0x1000, None, "aaa", "push mov cmp jne call pop ret")];
        let near = facts(0x2000, None, "bbb", "push mov cmp jne call pop ret");
        let far = facts(0x3000, None, "ccc", "push xor div mul shl call pop ret");
        let report = diff(&old, &[far, near], &DiffOptions::default());
        assert_eq!(report.matched.len(), 1);
        assert_eq!(report.matched[0].new.address, 0x2000);
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.added[0].address, 0x3000);
    }

    #[test]
    fn the_threshold_governs_structural_matches_only() {
        let old = vec![
            facts(0x1000, Some("named"), "aaa", "push mov call ret"),
            facts(0x2000, None, "ccc", "push mov cmp jne call pop ret"),
        ];
        let new = vec![
            facts(0x5000, Some("named"), "bbb", "xor div mul shl ret"),
            facts(0x6000, None, "ddd", "push mov cmp je call pop ret"),
        ];
        // A floor of 1.0 admits no structural match, but the name is
        // believed however the code changed.
        let strict = DiffOptions {
            min_similarity: 1.0,
        };
        let report = diff(&old, &new, &strict);
        assert_eq!(report.matched.len(), 1);
        assert_eq!(report.matched[0].kind, MatchKind::Name);
        // The default floor admits the shape match too.
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 2);
    }

    #[test]
    fn the_whole_image_similarity_is_the_dice_of_the_match() {
        let old = vec![
            facts(0x1000, None, "aaa", "xor ret"),
            facts(0x2000, None, "bbb", "mov ret"),
        ];
        let new = vec![
            facts(0x5000, None, "aaa", "xor ret"),
            facts(0x6000, None, "ccc", "div mul shl ret"),
            facts(0x7000, None, "ddd", "add sub or and ret"),
        ];
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 1);
        // 2 * 1 / (2 + 3).
        assert!((report.similarity - 0.4).abs() < 1e-12);
        // Two empty versions are wholly alike.
        let empty = diff(&[], &[], &DiffOptions::default());
        assert_eq!(empty.similarity, 1.0);
        assert!(empty.matched.is_empty());
    }

    #[test]
    fn the_report_is_in_address_order() {
        let old = vec![
            facts(0x3000, None, "ccc", "xor ret"),
            facts(0x1000, None, "aaa", "mov ret"),
            facts(0x2000, None, "bbb", "add ret"),
        ];
        let new = vec![
            facts(0x9000, None, "aaa", "mov ret"),
            facts(0x8000, None, "ccc", "xor ret"),
        ];
        let report = diff(&old, &new, &DiffOptions::default());
        let olds: Vec<u64> = report.matched.iter().map(|p| p.old.address).collect();
        assert_eq!(olds, [0x1000, 0x3000]);
        assert_eq!(report.removed[0].address, 0x2000);
    }

    #[test]
    fn similarity_reads_the_code_the_shape_and_the_size() {
        let a = facts(0x1000, None, "aaa", "push mov cmp jne call pop ret");
        // The same words: alike in every reading.
        assert_eq!(similarity(&a, &a), 1.0);
        // The same shape and size, other words: the code reading falls.
        let other = facts(0x2000, None, "bbb", "xor div mul shl add sub or ret");
        let code_apart = similarity(&a, &other);
        assert!(code_apart < 0.6, "{code_apart}");
        // The same words, a longer body: the size reading falls.
        let grown = facts(
            0x3000,
            None,
            "ccc",
            "push mov cmp jne call pop ret nop nop nop nop",
        );
        assert!(similarity(&a, &grown) < 1.0);
        // Empty bodies are alike; an empty and a full one share only the
        // shape's zero-count readings: 0.3 * (2/3).
        let empty = facts(0x4000, None, "ddd", "");
        assert_eq!(similarity(&empty, &empty), 1.0);
        assert!((similarity(&empty, &a) - 0.2).abs() < 1e-12);
    }

    #[test]
    fn the_graph_counts_are_read_in_the_shape() {
        let mut a = facts(0x1000, None, "aaa", "push mov cmp jne call pop ret");
        let mut b = facts(0x2000, None, "bbb", "push mov cmp jne call pop ret");
        a.blocks = 4;
        a.edges = 5;
        b.blocks = 4;
        b.edges = 5;
        let with_shape = similarity(&a, &b);
        b.blocks = 1;
        b.edges = 0;
        let without_shape = similarity(&a, &b);
        assert!(with_shape > without_shape);
    }

    #[test]
    fn a_hash_match_is_taken_before_a_name_match() {
        // The old name matches one new function, but its hash matches
        // another: the hash is the stronger evidence and takes the pair.
        let old = vec![facts(0x1000, Some("f"), "aaa", "xor ret")];
        let new = vec![
            facts(0x2000, Some("f"), "bbb", "mov ret"),
            facts(0x3000, Some("g"), "aaa", "xor ret"),
        ];
        let report = diff(&old, &new, &DiffOptions::default());
        assert_eq!(report.matched.len(), 1);
        assert_eq!(report.matched[0].new.address, 0x3000);
        assert_eq!(report.matched[0].kind, MatchKind::Hash);
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.added[0].address, 0x2000);
    }

    #[test]
    fn the_report_round_trips_as_json() {
        let old = vec![facts(0x1000, Some("f"), "aaa", "xor ret")];
        let new = vec![facts(0x2000, Some("f"), "aaa", "xor ret")];
        let report = diff(&old, &new, &DiffOptions::default());
        let text = serde_json::to_string(&report).expect("the report serializes");
        let read: DiffReport = serde_json::from_str(&text).expect("the report reads back");
        assert_eq!(read, report);
    }
}
