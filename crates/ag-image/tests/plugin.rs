//! A plugin's loader and architecture, registered in Rust, carry an image
//! the engine does not read through to the listing and the graph.

use std::sync::Arc;

use ag_engine::cpu_context::{DecodedInsn, Flow};
use ag_engine::plugin::{self, Architecture, DecodedSection, LoadedImage, Loader};
use ag_engine::Bitness;
use ag_image::{Binary, EdgeKind};

/// A toy container: `TOY!`, a byte of code length, then the code at 0x100.
struct ToyLoader;

impl Loader for ToyLoader {
    fn name(&self) -> &str {
        "toy-loader"
    }
    fn recognizes(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"TOY!")
    }
    fn load(&self, _name: &str, bytes: &[u8]) -> Result<LoadedImage, String> {
        let length = *bytes.get(4).ok_or("a toy file has a length byte")? as u64;
        Ok(LoadedImage {
            language: "TOYCPU:LE:32:default".to_string(),
            entry: Some(0x100),
            base: Some(0x100),
            sections: vec![ag_engine::image::Section {
                name: "code".to_string(),
                vma: 0x100,
                size: length,
                executable: true,
                file_offset: Some(5),
                file_size: Some(length),
            }],
            functions: vec![(0x100, "start".to_string())],
            data: Vec::new(),
            imports: Vec::new(),
        })
    }
}

/// A toy instruction set: one-byte `nop` (0) and `ret` (1); two-byte `jmp`
/// (2), `br` (3) and `call` (4) to 0x100 plus the second byte.
struct ToyCpu;

impl Architecture for ToyCpu {
    fn name(&self) -> &str {
        "toy-cpu"
    }
    fn languages(&self) -> Vec<String> {
        vec!["TOYCPU:LE:32:default".to_string()]
    }
    fn bitness(&self, _language: &str) -> Bitness {
        Bitness::Bits32
    }
    fn decode_section(
        &self,
        _language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        let mut decoded = DecodedSection::default();
        let mut at = 0usize;
        while at < bytes.len() {
            let address = base + at as u64;
            let (length, mnemonic, operands, flow) = match bytes[at] {
                0 => (1, "nop", String::new(), Flow::Next),
                1 => (1, "ret", String::new(), Flow::Return),
                op @ 2..=4 => {
                    let target = 0x100 + *bytes.get(at + 1).ok_or("a short jump")? as u64;
                    let (name, flow) = match op {
                        2 => ("jmp", Flow::UnconditionalBranch(target)),
                        3 => ("br", Flow::ConditionalBranch(target)),
                        _ => ("call", Flow::Call(target)),
                    };
                    (2, name, format!("{target:#x}"), flow)
                }
                _ => (1, "(bad)", String::new(), Flow::Invalid),
            };
            decoded.disasm.instructions.push(DecodedInsn {
                address,
                length,
                mnemonic: 0,
                flow,
                operands: Vec::new(),
                register_uses: Vec::new(),
                rip_relative_address: None,
                absolute_address: None,
                switch_indices: false,
                opcode: 0,
                flags_read: 0,
                flags_written: 0,
            });
            decoded
                .text
                .insert(address, (mnemonic.to_string(), operands, Vec::new()));
            at += length;
        }
        Ok(decoded)
    }
}

#[test]
fn a_plugins_image_is_listed_graphed_and_reported_like_any_other() {
    plugin::register_loader(Arc::new(ToyLoader));
    plugin::register_architecture(Arc::new(ToyCpu));
    /// The toy file, removed when the test ends however it ends.
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = Scratch(std::env::temp_dir().join(format!(
        "ag-image-plugin-{}-{:?}.toy",
        std::process::id(),
        std::thread::current().id()
    )));
    // 0x100: br 0x104; 0x102: nop; 0x103: ret; 0x104: nop; 0x105: ret.
    std::fs::write(&path.0, b"TOY!\x06\x03\x04\x00\x01\x00\x01").unwrap();
    let image = Binary::open(&path.0).expect("the toy loader reads the file");

    assert_eq!(image.language(), "TOYCPU:LE:32:default");
    assert_eq!(image.plugin_architecture().as_deref(), Some("toy-cpu"));
    assert!(image.supports_disassembly());
    assert!(!image.supports_pseudocode());
    assert_eq!(image.entry(), Some(0x100));
    assert_eq!(image.base(), Some(0x100));
    assert_eq!(image.functions().len(), 1);
    assert_eq!(image.function_name(0x100), Some("start"));
    assert_eq!(image.sections().len(), 1);
    assert_eq!(image.bytes_at(0x100, 2), Some(vec![3, 4]));

    let listing = image.disassembly(0x100).expect("the toy code decodes");
    let text: Vec<(u64, String, String)> = listing
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .map(|ins| (ins.address, ins.mnemonic.clone(), ins.operands.clone()))
        .collect();
    assert_eq!(
        text,
        [
            (0x100, "br".to_string(), "0x104".to_string()),
            (0x102, "nop".to_string(), String::new()),
            (0x103, "ret".to_string(), String::new()),
            (0x104, "nop".to_string(), String::new()),
            (0x105, "ret".to_string(), String::new()),
        ]
    );
    let graph = image.control_flow(0x100).expect("a graph");
    let mut starts: Vec<u64> = graph.blocks.iter().map(|block| block.from).collect();
    starts.sort_unstable();
    assert_eq!(starts, [0x100, 0x102, 0x104]);
    let mut edges: Vec<(u64, u64, EdgeKind)> = graph
        .edges
        .iter()
        .map(|edge| (edge.from, edge.to, edge.kind))
        .collect();
    edges.sort_by_key(|(from, to, _)| (*from, *to));
    assert_eq!(
        edges,
        [
            (0x100, 0x102, EdgeKind::Fallthrough),
            (0x100, 0x104, EdgeKind::Taken),
        ]
    );
    assert!(image.pseudocode(0x100).is_err());
}
