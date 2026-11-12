//! `ag image … binexport`: the analysis as a BinExport file, run against
//! the sample ELF. The file is read back off the protobuf wire here, by
//! field number, the way `binexport2.proto` lays the message out.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-engine/tests/fixtures")
        .join(name)
}

/// A unique temporary path stem, so parallel tests do not share a file.
fn stem(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ag-cli-binexport-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

/// Run `ag` with `args`, returning its stdout, and assert it succeeded.
fn ag(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(args)
        .output()
        .expect("the ag binary runs");
    assert!(
        output.status.success(),
        "ag {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// One field of a message: its number, and its varint or its bytes.
enum Field {
    Varint(u64),
    Bytes(Vec<u8>),
}

fn varint(bytes: &mut &[u8]) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = bytes[0];
        *bytes = &bytes[1..];
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

/// The fields of a message, in the order they were written.
fn fields(mut bytes: &[u8]) -> Vec<(u32, Field)> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let tag = varint(&mut bytes);
        let field = (tag >> 3) as u32;
        match tag & 7 {
            0 => out.push((field, Field::Varint(varint(&mut bytes)))),
            2 => {
                let length = varint(&mut bytes) as usize;
                out.push((field, Field::Bytes(bytes[..length].to_vec())));
                bytes = &bytes[length..];
            }
            other => panic!("wire type {other} is not one BinExport uses"),
        }
    }
    out
}

/// Every length-delimited value of `field`.
fn all(message: &[(u32, Field)], field: u32) -> Vec<Vec<u8>> {
    message
        .iter()
        .filter_map(|(number, value)| match value {
            Field::Bytes(bytes) if *number == field => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

/// The first varint value of `field`.
fn number(message: &[(u32, Field)], field: u32) -> Option<u64> {
    message.iter().find_map(|(number, value)| match value {
        Field::Varint(value) if *number == field => Some(*value),
        _ => None,
    })
}

/// The call graph's vertices: each one's address, type and name.
fn vertices(message: &[(u32, Field)]) -> Vec<(u64, u64, Option<String>)> {
    let graph = fields(&all(message, 8)[0]);
    all(&graph, 1)
        .iter()
        .map(|vertex| {
            let vertex = fields(vertex);
            (
                number(&vertex, 1).expect("a vertex has an address"),
                number(&vertex, 2).unwrap_or(0),
                all(&vertex, 3)
                    .first()
                    .map(|name| String::from_utf8(name.clone()).unwrap()),
            )
        })
        .collect()
}

#[test]
fn the_image_is_written_as_a_binexport_file() {
    let sample = fixture("sample.elf");
    let file = stem("plain").with_extension("BinExport");
    let said = ag(&[
        "image",
        sample.to_str().unwrap(),
        "binexport",
        file.to_str().unwrap(),
    ]);
    assert!(said.starts_with("wrote "), "{said}");
    assert!(said.contains("14 functions"), "{said}");
    assert!(said.contains("12 flow graphs"), "{said}");

    let bytes = std::fs::read(&file).expect("the file was written");
    assert!(said.contains(&format!("{} bytes", bytes.len())), "{said}");
    let message = fields(&bytes);

    // The meta names the binary: its file, its SHA-256, its architecture.
    let meta = fields(&all(&message, 1)[0]);
    assert_eq!(all(&meta, 1), [b"sample.elf".to_vec()]);
    let id = String::from_utf8(all(&meta, 2)[0].clone()).unwrap();
    assert_eq!(id.len(), 64);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(all(&meta, 3), [b"x86-64".to_vec()]);
    assert!(number(&meta, 4).unwrap() > 1_700_000_000);

    // The call graph is in address order, and names what the image names:
    // main, the stub of printf, and the import it jumps to.
    let vertices = vertices(&message);
    assert!(vertices.windows(2).all(|pair| pair[0].0 < pair[1].0));
    assert!(vertices.contains(&(0x1198, 0, Some("main".to_string()))));
    assert!(vertices.contains(&(0x1050, 3, Some("printf".to_string()))));
    assert!(vertices.contains(&(0x3fd0, 2, Some("printf".to_string()))));

    // One flow graph a function that was disassembled, and the tables
    // they are made of.
    assert_eq!(all(&message, 7).len(), 12);
    assert_eq!(all(&message, 5).len(), 119, "the instructions");
    assert!(!all(&message, 2).is_empty(), "the expressions");
    assert!(!all(&message, 3).is_empty(), "the operands");
    assert!(!all(&message, 6).is_empty(), "the basic blocks");
    let mnemonics: Vec<Vec<u8>> = all(&message, 4)
        .iter()
        .map(|mnemonic| all(&fields(mnemonic), 1)[0].clone())
        .collect();
    assert_eq!(mnemonics[0], b"mov", "the commonest mnemonic is the first");
    // The string main prints is in the table.
    assert!(all(&message, 9)
        .iter()
        .any(|string| string.starts_with(b"%ld")));

    let _ = std::fs::remove_file(&file);
}

#[test]
fn the_projects_renames_and_comments_are_written() {
    let sample = fixture("sample.elf");
    let stem = stem("project");
    let project = stem.with_extension("agproj");
    let file = stem.with_extension("BinExport");
    let _ = std::fs::remove_file(&project);
    let target = sample.to_str().unwrap();
    let path = project.to_str().unwrap();
    ag(&[
        "project",
        target,
        "rename",
        "--file",
        path,
        "0x1198",
        "entry_point",
    ]);
    ag(&[
        "project",
        target,
        "comment",
        "--file",
        path,
        "0x11b5",
        "adds three",
    ]);

    ag(&[
        "image",
        target,
        "binexport",
        file.to_str().unwrap(),
        "--project",
        path,
    ]);
    let message = fields(&std::fs::read(&file).expect("the file was written"));

    assert!(vertices(&message).contains(&(0x1198, 0, Some("entry_point".to_string()))));
    // The comment is in the string table, and one comment names it.
    let strings = all(&message, 9);
    let index = strings
        .iter()
        .position(|string| string == b"adds three")
        .expect("the comment's text is in the string table");
    let comments = all(&message, 17);
    assert_eq!(comments.len(), 1);
    assert_eq!(number(&fields(&comments[0]), 4), Some(index as u64));

    let _ = std::fs::remove_file(&project);
    let _ = std::fs::remove_file(&file);
}
