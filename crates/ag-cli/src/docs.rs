//! `ag docs` — the reference manual, compiled into the binary.
//!
//! A session driving `ag` may have the binary and nothing else: no checkout, no
//! `docs/` tree, no network. Every topic below is therefore pulled in with
//! `include_str!` at compile time and answered out of the binary's own
//! rodata, so `ag docs` opens no file and resolves no path.
//!
//! Compiling the bytes in also fixes the freshness hazard the other way: the
//! documents duplicate sections of the README, and a test holds the embedded
//! copy to the README it was written from.

use std::fmt::Write as _;

/// One embedded document.
pub struct Doc {
    /// The name `ag docs <topic>` answers to.
    pub topic: &'static str,
    /// One line about the topic, for the list.
    pub summary: &'static str,
    /// The README sections this document duplicates.
    ///
    /// A document that duplicates none lists nothing here. The mapping is
    /// what the sync test holds the embedded bytes to.
    #[cfg_attr(not(test), allow(dead_code))]
    pub readme_sections: &'static [&'static str],
    /// The document itself.
    pub body: &'static str,
}

/// The documents, in the order an agent reaches for them: the commands first,
/// then the layout they read, then the options that tune the output, then
/// the other tool in the workspace.
pub const DOCS: &[Doc] = &[
    Doc {
        topic: "cli",
        summary: "Every subcommand, option and exit code of the ag binary.",
        readme_sections: &[
            "Build",
            "Corpus CLI",
            "Image CLI",
            "Embedded manual and agent skill",
        ],
        body: include_str!("../../../docs/cli.md"),
    },
    Doc {
        topic: "corpus-format",
        summary: "The indexed corpus layout and the kuna project export layout, field by field.",
        readme_sections: &["Corpus format"],
        body: include_str!("../../../docs/corpus-format.md"),
    },
    Doc {
        topic: "project-format",
        summary: "The portable project file: the analysis's identity and the analyst's changes.",
        readme_sections: &[],
        body: include_str!("../../../docs/project-format.md"),
    },
    Doc {
        topic: "options",
        summary:
            "The engine's options, symptom index first: if the output shows X, try --option Y.",
        readme_sections: &[],
        body: include_str!("../../../docs/options.md"),
    },
    Doc {
        topic: "il",
        summary: "The intermediate languages: four levels of the lift, each with an SSA form, mapped onto each other.",
        readme_sections: &["Intermediate languages"],
        body: include_str!("../../../docs/il.md"),
    },
    Doc {
        topic: "plugins",
        summary: "The plugin SDK: loaders, architectures and tools, in Rust or as commands declared in a manifest.",
        readme_sections: &["Plugins"],
        body: include_str!("../../../docs/plugins.md"),
    },
    Doc {
        topic: "scripting",
        summary: "Scripts against the image: ag run, the tool protocol, and the Python client.",
        readme_sections: &["Scripting"],
        body: include_str!("../../../docs/scripting.md"),
    },
    Doc {
        topic: "workbench",
        summary: "The panes of ag-ui, and the kuna JSON surfaces it reads.",
        readme_sections: &["Desktop workbench"],
        body: include_str!("../../../docs/workbench.md"),
    },
];

/// The README the documents are kept in step with.
#[cfg(test)]
const README: &str = include_str!("../../../README.md");

/// Print the manual.
///
/// Without a topic the topics are listed; with one, that document is printed.
/// A topic nobody wrote is a usage error.
pub fn run(topic: Option<&str>) -> i32 {
    match topic {
        Some(name) => match lookup(name) {
            Some(doc) => {
                print!("{}", doc.body);
                0
            }
            None => {
                eprintln!("error: no embedded doc named {name:?}");
                eprintln!("known topics: {}", topic_names().join(", "));
                2
            }
        },
        None => {
            print!("{}", render_list());
            eprintln!("\nread one with `ag docs <topic>`");
            0
        }
    }
}

/// Resolve a caller-supplied topic.
///
/// Agents reach for the file name they saw in a doc map (`corpus-format.md`,
/// `docs/corpus-format.md`) as often as for the bare topic, and singular and
/// plural are a coin flip, so all of those land on the same page rather than
/// on an error.
pub fn lookup(name: &str) -> Option<&'static Doc> {
    let lowered = name.to_ascii_lowercase();
    let trimmed = lowered
        .trim_start_matches("./")
        .trim_start_matches("docs/")
        .trim_end_matches(".md")
        .replace('_', "-");

    DOCS.iter().find(|doc| {
        doc.topic == trimmed
            || doc.topic.trim_end_matches('s') == trimmed.trim_end_matches('s')
            || (doc.topic == "cli"
                && matches!(trimmed.as_str(), "command" | "commands" | "reference"))
    })
}

/// The names of every topic.
pub fn topic_names() -> Vec<&'static str> {
    DOCS.iter().map(|doc| doc.topic).collect()
}

/// The list of topics, one per line.
pub fn render_list() -> String {
    let width = DOCS.iter().map(|doc| doc.topic.len()).max().unwrap_or(0);
    let mut out = String::new();

    for doc in DOCS {
        let _ = writeln!(
            out,
            "{:width$}  {:>7}  {}",
            doc.topic,
            human_size(doc.body.len()),
            doc.summary
        );
    }

    out
}

/// A size a reader can weigh at a glance.
pub fn human_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{} KB", bytes.div_ceil(1024))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_topic_is_embedded_and_nonempty() {
        assert!(DOCS.len() >= 3);
        for doc in DOCS {
            assert!(!doc.body.is_empty(), "{} embedded empty", doc.topic);
            assert!(
                doc.body.starts_with('#'),
                "{} is not a markdown file",
                doc.topic
            );
        }
    }

    #[test]
    fn topics_are_unique_and_resolvable() {
        let mut seen: Vec<&str> = Vec::new();
        for doc in DOCS {
            assert!(!seen.contains(&doc.topic), "duplicate topic {}", doc.topic);
            seen.push(doc.topic);
            assert_eq!(lookup(doc.topic).unwrap().topic, doc.topic);
        }
    }

    #[test]
    fn lookup_forgives_the_shapes_agents_type() {
        for name in [
            "corpus-format",
            "corpus_format",
            "CORPUS-FORMAT",
            "corpus-format.md",
            "docs/corpus-format.md",
        ] {
            assert_eq!(lookup(name).unwrap().topic, "corpus-format", "{name}");
        }
        assert_eq!(lookup("commands").unwrap().topic, "cli");
        assert!(lookup("nonesuch").is_none());
    }

    #[test]
    fn the_embedded_documents_match_the_readme_sections_they_duplicate() {
        for doc in DOCS {
            for section in doc.readme_sections {
                let text = readme_section(section)
                    .unwrap_or_else(|| panic!("the README has no {section:?} section"));

                for command in sh_commands(&text) {
                    assert!(
                        doc.body.contains(command.as_str()),
                        "{}: the README command {command:?} is not in the document",
                        doc.topic
                    );
                }

                for token in inline_tokens(&text) {
                    assert!(
                        doc.body.contains(token.as_str()),
                        "{}: the README mentions {token:?}, which the document does not",
                        doc.topic
                    );
                }
            }
        }
    }

    /// One section of the README, without its heading.
    fn readme_section(heading: &str) -> Option<String> {
        let marker = format!("\n## {heading}\n");
        let start = README.find(&marker)? + marker.len();
        let rest = &README[start..];
        let end = rest.find("\n## ").unwrap_or(rest.len());

        Some(rest[..end].to_string())
    }

    /// The commands of the `sh` blocks of a section.
    fn sh_commands(section: &str) -> Vec<String> {
        let mut commands = Vec::new();
        let mut block: Option<String> = None;

        for line in section.lines() {
            let line = line.trim();

            if line.starts_with("```") {
                if block.is_none() {
                    block = Some(line.trim_start_matches('`').trim().to_string());
                } else {
                    block = None;
                }
                continue;
            }

            if block.as_deref() == Some("sh") && !line.is_empty() && !line.starts_with('#') {
                commands.push(line.to_string());
            }
        }

        commands
    }

    /// The inline code of a section, without the fenced blocks.
    ///
    /// Only the names that name a file, a flag or a path are kept: those are
    /// the ones a document has to agree with.
    fn inline_tokens(section: &str) -> Vec<String> {
        let prose = without_code_blocks(section);
        let mut tokens = Vec::new();
        let mut rest = prose.as_str();

        while let Some(start) = rest.find('`') {
            rest = &rest[start + 1..];
            let Some(end) = rest.find('`') else { break };
            let token = &rest[..end];
            rest = &rest[end + 1..];

            if token.contains('.') || token.contains('-') {
                tokens.push(token.to_string());
            }
        }

        tokens
    }

    /// A section with its fenced blocks taken out.
    fn without_code_blocks(section: &str) -> String {
        let mut out = String::new();
        let mut rest = section;
        let mut in_block = false;

        while let Some(start) = rest.find("```") {
            let (before, after) = rest.split_at(start);
            if !in_block {
                out.push_str(before);
            }
            in_block = !in_block;
            rest = &after[3..];
        }

        if !in_block {
            out.push_str(rest);
        }

        out
    }
}
