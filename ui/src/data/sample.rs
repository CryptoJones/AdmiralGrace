//! A [`Provider`] over fabricated data.
//!
//! The sample project mirrors the layout reference in `ui/wireframe.html`.
//! It exists so the workbench can be exercised — and reviewed — before a
//! binary pipeline exists, and so capability-gated views have something to
//! show. It is never presented as real analysis.

use crate::data::{
    AnalysisState, ByteLine, FunctionDetail, FunctionRow, HitKind, ListingLine, Problem, Provider,
    Reference, ReferenceKind, SearchHit, SectionCounts,
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
        line(start + 48, "F4 03 00 AA", "mov", "x20, x0", None),
        line(start + 52, "E1 03 13 AA", "mov", "x1, x19", None),
        line(start + 56, "22 00 00 94", "bl", "AES_GCM_open", None),
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
