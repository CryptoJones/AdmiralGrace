//! A [`Provider`] over fabricated data.
//!
//! The sample project mirrors the layout reference in `ui/wireframe.html`.
//! It exists so the workbench can be exercised — and reviewed — before a
//! binary pipeline exists, and so capability-gated views have something to
//! show. It is never presented as real analysis.

use crate::data::{
    AnalysisState, ByteLine, FunctionDetail, FunctionRow, Graph, GraphBlock, HitKind, ListingLine,
    Problem, Provider, Reference, ReferenceKind, SearchHit, SectionCounts,
};
use crate::model::{Capabilities, Project, ProjectKind};

struct SampleFunction {
    detail: FunctionDetail,
    listing: Vec<ListingLine>,
    pseudocode: String,
    bytes: Vec<ByteLine>,
    references: Vec<Reference>,
}

struct Sample {
    name: String,
    status: String,
    size: u64,
    objc: bool,
    body: SampleFunction,
}

/// The fabricated project used to exercise the workbench layout.
pub struct SampleProvider {
    project: Project,
    functions: Vec<Sample>,
}

impl SampleProvider {
    /// Build the sample project.
    pub fn new() -> Self {
        let functions = vec![
            sample_decrypt(),
            sample_parse_envelope(),
            sample_aes_gcm_open(),
            sample_verify_signature(),
            sample_sub(),
        ];

        Self {
            project: Project {
                name: "libsignal.dylib".into(),
                kind: ProjectKind::Sample,
                root: None,
                target_sha256: Some(
                    "0000000000000000000000000000000000000000000000000000000000000000".into(),
                ),
                provider: "sample".into(),
                architecture: Some("ARM64".into()),
                format: Some("Mach-O".into()),
            },
            functions,
        }
    }

    fn index_of(&self, address: u64) -> Option<usize> {
        self.functions
            .iter()
            .position(|f| f.body.detail.start == Some(address))
    }
}

impl Default for SampleProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for SampleProvider {
    fn project(&self) -> Project {
        self.project.clone()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            listing: true,
            pseudocode: true,
            graph: true,
            bytes: true,
            references: true,
            strings: true,
            segments: true,
            imports: true,
            exports: true,
            types: true,
            bookmarks: true,
            objc_methods: true,
        }
    }

    fn analysis_state(&self) -> AnalysisState {
        AnalysisState::Complete
    }

    fn functions(&self) -> Vec<FunctionRow> {
        self.functions
            .iter()
            .map(|f| FunctionRow {
                address: f.body.detail.start.unwrap_or_default(),
                name: f.name.clone(),
                status: f.status.clone(),
                size: Some(f.size),
                objc: f.objc,
            })
            .collect()
    }

    fn function_detail(&self, address: u64) -> Option<FunctionDetail> {
        let index = self.index_of(address)?;
        Some(self.functions[index].body.detail.clone())
    }

    fn listing(&self, address: u64) -> Option<Vec<ListingLine>> {
        let index = self.index_of(address)?;
        Some(self.functions[index].body.listing.clone())
    }

    /// The control-flow graph of a function.
    ///
    /// The blocks are cut out of the listing here, so the edges between
    /// them are worked out by the shared rule, the one the CLI reports by.
    fn graph(&self, address: u64) -> Option<Graph> {
        let index = self.index_of(address)?;
        let blocks = blocks_of(&self.functions[index].body.listing);

        Some(Graph {
            edges: Graph::edges_of_blocks(&blocks),
            blocks,
        })
    }

    fn pseudocode(&self, address: u64) -> Option<String> {
        let index = self.index_of(address)?;
        Some(self.functions[index].body.pseudocode.clone())
    }

    fn bytes(&self, address: u64) -> Option<Vec<ByteLine>> {
        let index = self.index_of(address)?;
        Some(self.functions[index].body.bytes.clone())
    }

    fn references(&self, address: u64) -> Vec<Reference> {
        let index = match self.index_of(address) {
            Some(index) => index,
            None => return Vec::new(),
        };
        self.functions[index].body.references.clone()
    }

    fn counts(&self) -> SectionCounts {
        SectionCounts {
            functions: 1248,
            imports: 318,
            exports: 74,
            strings: 2106,
            segments: 12,
            types: 86,
            bookmarks: 4,
        }
    }

    fn search(&self, query: &str, _deep: bool) -> Vec<SearchHit> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Vec::new();
        }

        let mut hits = Vec::new();

        for function in &self.functions {
            if function.name.to_lowercase().contains(&needle) {
                hits.push(SearchHit {
                    address: function.body.detail.start.unwrap_or_default(),
                    title: function.name.clone(),
                    detail: "Function".into(),
                    kind: HitKind::Function,
                });
            }

            for reference in &function.body.references {
                if reference.kind == ReferenceKind::String
                    && reference.label.to_lowercase().contains(&needle)
                {
                    hits.push(SearchHit {
                        address: reference.address,
                        title: reference.label.clone(),
                        detail: "String".into(),
                        kind: HitKind::String,
                    });
                }
            }
        }

        hits
    }

    fn problems(&self) -> Vec<Problem> {
        vec![Problem {
            message: "2 functions have no recoverable control flow".into(),
            address: Some(0x1000A12F0),
            action: Some("Open the function to inspect its listing".into()),
        }]
    }
}

fn sample_decrypt() -> Sample {
    let start = 0x100084A20;
    let listing = vec![
        line(
            start,
            "FD 7B BF A9",
            "stp",
            "x29, x30, [sp, #-0x10]!",
            Some("save frame"),
        ),
        line(start + 4, "FD 03 00 91", "mov", "x29, sp", None),
        line(
            start + 8,
            "F4 4F 01 A9",
            "stp",
            "x20, x19, [sp, #0x10]",
            None,
        ),
        line(
            start + 12,
            "F6 57 02 A9",
            "stp",
            "x22, x21, [sp, #0x20]",
            None,
        ),
        line(
            start + 16,
            "FD 7B 03 A9",
            "stp",
            "x29, x30, [sp, #0x30]",
            Some("save frame and link registers"),
        ),
        line(start + 20, "FD C3 00 91", "add", "x29, sp, #0x30", None),
        line(start + 24, "F3 03 00 AA", "mov", "x19, x0", None),
        line(start + 28, "E0 03 01 AA", "mov", "x0, x1", None),
        line(
            start + 32,
            "01 00 00 94",
            "bl",
            "parseEnvelope",
            Some("CODE XREF: decryptMessage+0x20"),
        ),
        line(start + 36, "E0 03 00 AA", "mov", "x0, x0", None),
        line(start + 40, "40 00 00 B4", "cbz", "x0, loc_100084A50", None),
        line(start + 44, "09 00 00 14", "b", "loc_100084A70", None),
        line(start + 48, "40 00 00 D2", "mov", "x0, #0", None),
        line(start + 52, "20 00 00 B9", "str", "x0, [x19]", None),
        line(start + 56, "E1 00 00 AA", "mov", "x1, #0", None),
        line(start + 60, "21 00 00 B9", "str", "x1, [x20]", None),
        line(start + 64, "42 00 00 AA", "mov", "x2, #0", None),
        line(start + 68, "22 00 00 B9", "str", "x2, [x21]", None),
        line(start + 72, "63 00 00 AA", "mov", "x3, #0", None),
        line(start + 76, "63 00 00 14", "b", "loc_100084A80", None),
        line(start + 80, "F4 03 00 AA", "mov", "x20, x0", None),
        line(start + 84, "E1 03 13 AA", "mov", "x1, x19", None),
        line(start + 88, "22 00 00 94", "bl", "AES_GCM_open", None),
        line(start + 92, "63 00 00 14", "b", "loc_100084A80", None),
        line(
            start + 96,
            "FD 7B C1 A9",
            "ldp",
            "x29, x30, [sp], #0x10",
            None,
        ),
        line(start + 100, "C0 03 5F D6", "ret", "", None),
    ];

    let bytes = (0..4)
        .map(|i| ByteLine {
            address: start + i * 16,
            bytes: (0..16)
                .map(|j| (start as u8).wrapping_add((i * 16 + j) as u8))
                .collect(),
        })
        .collect();

    Sample {
        name: "-[SignalService decryptMessage:]".into(),
        status: "Analyzed".into(),
        size: 0x1B8,
        objc: true,
        body: SampleFunction {
            detail: FunctionDetail {
                name: "-[SignalService decryptMessage:]".into(),
                status: "Analyzed".into(),
                start: Some(start),
                end: Some(start + 0x1B8),
                provenance: "Decoder · AArch64 instruction decode".into(),
                summary: "Name comes from an imported Objective-C method map. Target resolved from a relative branch offset.".into(),
            },
            listing,
            pseudocode: "void decryptMessage(SignalService *self, void *ciphertext) {\n    Envelope *env = parseEnvelope(ciphertext);\n    if (env == NULL) {\n        return;\n    }\n    AES_GCM_open(env);\n}".into(),
            bytes,
            references: vec![
                Reference {
                    address: 0x100081D60,
                    label: "parseEnvelope".into(),
                    kind: ReferenceKind::Calls,
                },
                Reference {
                    address: 0x10017B2C0,
                    label: "AES_GCM_open".into(),
                    kind: ReferenceKind::Calls,
                },
                Reference {
                    address: 0x1000C1100,
                    label: "-[Conversation decrypt:]".into(),
                    kind: ReferenceKind::CalledBy,
                },
                Reference {
                    address: 0x1001A2038,
                    label: "\"parseEnvelope failed\"".into(),
                    kind: ReferenceKind::String,
                },
            ],
        },
    }
}

fn sample_parse_envelope() -> Sample {
    let start = 0x100081D60;
    Sample {
        name: "parseEnvelope".into(),
        status: "Analyzed".into(),
        size: 0x240,
        objc: false,
        body: SampleFunction {
            detail: FunctionDetail {
                name: "parseEnvelope".into(),
                status: "Analyzed".into(),
                start: Some(start),
                end: Some(start + 0x240),
                provenance: "Imported symbol".into(),
                summary: "Name comes from the dynamic symbol table.".into(),
            },
            listing: vec![
                line(start, "FD 7B BF A9", "stp", "x29, x30, [sp, #-0x10]!", None),
                line(start + 4, "00 00 00 94", "bl", "malloc", None),
                line(start + 8, "FD 03 00 91", "mov", "x29, sp", None),
            ],
            pseudocode: "Envelope *parseEnvelope(const void *data) {\n    return malloc(sizeof(Envelope));\n}".into(),
            bytes: Vec::new(),
            references: vec![Reference {
                address: 0x100084A40,
                label: "-[SignalService decryptMessage:]".into(),
                kind: ReferenceKind::CalledBy,
            }],
        },
    }
}

fn sample_aes_gcm_open() -> Sample {
    let start = 0x10017B2C0;
    Sample {
        name: "AES_GCM_open".into(),
        status: "Analyzed".into(),
        size: 0x90,
        objc: false,
        body: SampleFunction {
            detail: FunctionDetail {
                name: "AES_GCM_open".into(),
                status: "Analyzed".into(),
                start: Some(start),
                end: Some(start + 0x90),
                provenance: "Imported symbol".into(),
                summary: "Name comes from the dynamic symbol table.".into(),
            },
            listing: vec![line(start, "C0 03 5F D6", "ret", "", None)],
            pseudocode: "int AES_GCM_open(Envelope *env) {\n    return 0;\n}".into(),
            bytes: Vec::new(),
            references: vec![Reference {
                address: 0x100084A58,
                label: "-[SignalService decryptMessage:]".into(),
                kind: ReferenceKind::CalledBy,
            }],
        },
    }
}

fn sample_verify_signature() -> Sample {
    let start = 0x10009C410;
    Sample {
        name: "verifySignature".into(),
        status: "Analyzed".into(),
        size: 0x320,
        objc: false,
        body: SampleFunction {
            detail: FunctionDetail {
                name: "verifySignature".into(),
                status: "Analyzed".into(),
                start: Some(start),
                end: Some(start + 0x320),
                provenance: "Imported symbol".into(),
                summary: "Name comes from the dynamic symbol table.".into(),
            },
            listing: vec![line(start, "C0 03 5F D6", "ret", "", None)],
            pseudocode:
                "bool verifySignature(const uint8_t *sig, size_t len) {\n    return false;\n}"
                    .into(),
            bytes: Vec::new(),
            references: Vec::new(),
        },
    }
}

fn sample_sub() -> Sample {
    let start = 0x1000A12F0;
    Sample {
        name: "sub_1000A12F0".into(),
        status: "Partial".into(),
        size: 0x64,
        objc: false,
        body: SampleFunction {
            detail: FunctionDetail {
                name: "sub_1000A12F0".into(),
                status: "Partial".into(),
                start: Some(start),
                end: Some(start + 0x64),
                provenance: "Analysis inference".into(),
                summary: "No symbol matched this address; the name was generated.".into(),
            },
            listing: vec![line(start, "C0 03 5F D6", "ret", "", None)],
            pseudocode: String::new(),
            bytes: Vec::new(),
            references: Vec::new(),
        },
    }
}

fn line(
    address: u64,
    bytes: &str,
    mnemonic: &str,
    operands: &str,
    comment: Option<&str>,
) -> ListingLine {
    ListingLine {
        address,
        bytes: bytes.to_string(),
        mnemonic: mnemonic.to_string(),
        operands: operands.to_string(),
        comment: comment.map(str::to_string),
    }
}

/// The blocks of a function, worked out from its listing.
///
/// The listing is cut at the branches: every run of instructions between
/// two branches is a block, and the block knows where the code goes next.
fn blocks_of(listing: &[ListingLine]) -> Vec<GraphBlock> {
    let mut blocks: Vec<GraphBlock> = Vec::new();
    let mut open: Vec<ListingLine> = Vec::new();

    for (index, line) in listing.iter().enumerate() {
        open.push(line.clone());

        let Some(branch) = branch_of(line) else {
            continue;
        };

        let from = open[0].address;
        let to = after(&open);

        let mut successors = Vec::new();

        if let Some(target) = branch.target {
            successors.push(target);
        }

        // The code falls into the next instruction when the listing goes
        // on right there.
        if branch.falls_through && listing.get(index + 1).map(|line| line.address) == Some(to) {
            successors.push(to);
        }

        blocks.push(GraphBlock {
            from,
            to,
            successors,
            instructions: std::mem::take(&mut open),
        });
    }

    // Whatever is left is the last block of the function.
    if !open.is_empty() {
        let from = open[0].address;
        let to = after(&open);

        blocks.push(GraphBlock {
            from,
            to,
            successors: Vec::new(),
            instructions: open,
        });
    }

    blocks
}

/// What a branch does to the flow of the code.
struct Branch {
    /// Where the branch goes, when it names an address.
    target: Option<u64>,
    /// Whether the code can fall into the next instruction.
    falls_through: bool,
}

/// The branch an instruction is, if it is one.
///
/// A call is not a branch: it comes back, so the code goes on where it
/// was.
fn branch_of(line: &ListingLine) -> Option<Branch> {
    let target = target_of(&line.operands);

    match line.mnemonic.trim() {
        "ret" => Some(Branch {
            target: None,
            falls_through: false,
        }),
        "b" | "br" => Some(Branch {
            target,
            falls_through: false,
        }),
        "cbz" | "cbnz" | "tbz" | "tbnz" => Some(Branch {
            target,
            falls_through: true,
        }),
        _ => None,
    }
}

/// The address a branch names, if it names one.
fn target_of(operands: &str) -> Option<u64> {
    operands
        .split_whitespace()
        .find_map(|token| token.strip_prefix("loc_"))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
}

/// The address just after the last instruction of a run.
fn after(instructions: &[ListingLine]) -> u64 {
    let Some(last) = instructions.last() else {
        return 0;
    };

    last.address + last.bytes.split_whitespace().count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listing_is_cut_at_the_branches() {
        let listing = vec![
            line(0x1000, "E0 03 01 AA", "mov", "x0, x1", None),
            line(0x1004, "40 00 00 B4", "cbz", "x0, loc_1010", None),
            line(0x1008, "E0 03 00 AA", "mov", "x0, x0", None),
            line(0x100C, "C0 03 5F D6", "ret", "", None),
        ];

        let blocks = blocks_of(&listing);

        assert_eq!(blocks.len(), 2, "the branch cuts the listing in two");

        let first = &blocks[0];
        assert_eq!(first.from, 0x1000);
        assert_eq!(first.to, 0x1008, "the block ends after the branch");
        assert_eq!(first.instructions.len(), 2);
        assert_eq!(
            first.successors,
            vec![0x1010, 0x1008],
            "the branch goes two ways: the target and the fall-through"
        );

        let last = &blocks[1];
        assert_eq!(last.from, 0x1008);
        assert_eq!(last.to, 0x1010);
        assert!(last.successors.is_empty(), "a return goes nowhere");
    }

    #[test]
    fn a_jump_does_not_fall_through() {
        let listing = vec![
            line(0x1000, "09 00 00 14", "b", "loc_1010", None),
            line(0x1004, "E0 03 00 AA", "mov", "x0, x0", None),
            line(0x1008, "C0 03 5F D6", "ret", "", None),
        ];

        let blocks = blocks_of(&listing);

        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].successors, vec![0x1010], "only the target");
    }

    #[test]
    fn a_call_is_not_a_branch() {
        let listing = vec![
            line(0x1000, "01 00 00 94", "bl", "other", None),
            line(0x1004, "C0 03 5F D6", "ret", "", None),
        ];

        let blocks = blocks_of(&listing);

        assert_eq!(blocks.len(), 1, "the call does not cut the block");
        assert_eq!(blocks[0].from, 0x1000);
        assert_eq!(blocks[0].to, 0x1008);
    }

    #[test]
    fn the_sample_function_has_a_graph_to_draw() {
        let provider = SampleProvider::new();

        let graph = provider.graph(0x100084A20).expect("the sample has a graph");

        assert_eq!(graph.blocks.len(), 5, "the sample function has five blocks");

        // The branch at the top of the function goes two ways.
        let first = &graph.blocks[0];
        assert_eq!(first.from, 0x100084A20);
        assert_eq!(first.successors.len(), 2);
        assert!(first.successors.contains(&0x100084A50), "the error path");
        assert!(first.successors.contains(&0x100084A4C), "the way on");
    }

    #[test]
    fn the_edges_of_the_sample_follow_the_same_rule_as_the_binary() {
        let provider = SampleProvider::new();

        let graph = provider.graph(0x100084A20).expect("the sample has a graph");

        assert!(!graph.edges.is_empty(), "the graph has edges");

        for edge in &graph.edges {
            let block = graph
                .blocks
                .iter()
                .find(|block| block.from == edge.from)
                .expect("the block the edge leaves");

            let expected = if edge.to == block.to {
                ag_image::EdgeKind::Fallthrough
            } else {
                ag_image::EdgeKind::Taken
            };

            assert_eq!(edge.kind, expected, "the edge {edge:?}");
        }

        // The branch at the top of the function goes two ways: one of them
        // falls off the end of the block, and the other one is taken.
        let first = &graph.blocks[0];
        let kinds: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| edge.from == first.from)
            .map(|edge| edge.kind)
            .collect();

        assert_eq!(kinds.len(), 2, "the branch goes two ways");
        assert!(kinds.contains(&ag_image::EdgeKind::Fallthrough));
        assert!(kinds.contains(&ag_image::EdgeKind::Taken));
    }
}
