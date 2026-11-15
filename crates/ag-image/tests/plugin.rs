//! A plugin's loader and architecture, registered in Rust, carry an image
//! the engine does not read through to the listing and the graph.

use std::sync::Arc;

use ag_engine::cpu_context::{DecodedInsn, Flow};
use ag_engine::plugin::{
    self, Architecture, DecodedSection, FunctionCode, LiftHook, LiftedGraph, LoadedImage, Loader,
    RecoveredBlock, Rewrite,
};
use ag_engine::ast::BinaryOp;
use ag_engine::{AstNode, Bitness, Node, Terminator};
use ag_image::{Binary, EdgeKind, Level};
use ag_image::FunctionProperties;
use std::collections::BTreeMap;

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
                rep: false,
                delay_slot: false,
            });
            decoded
                .text
                .insert(address, (mnemonic.to_string(), operands, Vec::new()));
            at += length;
        }
        Ok(decoded)
    }
}

/// The same container with another magic, for a language the lifting
/// architecture below reads.
struct ToyLoader2;

impl Loader for ToyLoader2 {
    fn name(&self) -> &str {
        "toy-loader-2"
    }
    fn recognizes(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"TOY2")
    }
    fn load(&self, name: &str, bytes: &[u8]) -> Result<LoadedImage, String> {
        let mut image = ToyLoader.load(name, bytes)?;
        image.language = "TOYLIFT:LE:32:default".to_string();
        Ok(image)
    }
}

/// The toy instruction set again, with a delay slot after every `jmp` and
/// `br` — the instruction after one belongs to its block — recovering its
/// own blocks, and lifting a whole function at once: each call a call, a
/// branch a test of `flag`.
struct ToyLifting;

impl Architecture for ToyLifting {
    fn name(&self) -> &str {
        "toy-lifting"
    }
    fn languages(&self) -> Vec<String> {
        vec!["TOYLIFT:LE:32:default".to_string()]
    }
    fn bitness(&self, _language: &str) -> Bitness {
        Bitness::Bits32
    }
    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        ToyCpu.decode_section(language, bytes, base)
    }
    fn lifts(&self, _language: &str) -> bool {
        true
    }
    fn blocks(
        &self,
        _language: &str,
        disasm: &ag_engine::Disasm,
        entry: u64,
    ) -> Option<Result<Vec<RecoveredBlock>, String>> {
        let at = |address: u64| {
            disasm
                .instructions
                .iter()
                .position(|ins| ins.address == address)
        };
        let end = disasm
            .instructions
            .last()
            .map_or(entry, |ins| ins.address + ins.length as u64);
        let mut blocks: Vec<RecoveredBlock> = Vec::new();
        let mut work = vec![entry];
        while let Some(start) = work.pop() {
            if blocks.iter().any(|block| block.from == start) {
                continue;
            }
            let Some(mut index) = at(start) else {
                continue;
            };
            let mut successors = Vec::new();
            let to = loop {
                let Some(ins) = disasm.instructions.get(index) else {
                    break end;
                };
                match ins.flow {
                    Flow::UnconditionalBranch(target) | Flow::ConditionalBranch(target) => {
                        // The delay slot is the branch's.
                        let after_slot = disasm
                            .instructions
                            .get(index + 2)
                            .map_or(end, |ins| ins.address);
                        successors.push(target);
                        if matches!(ins.flow, Flow::ConditionalBranch(_)) && after_slot < end {
                            successors.push(after_slot);
                        }
                        break after_slot;
                    }
                    Flow::Return => {
                        break disasm
                            .instructions
                            .get(index + 1)
                            .map_or(end, |ins| ins.address);
                    }
                    _ => index += 1,
                }
            };
            work.extend(successors.iter().copied());
            blocks.push(RecoveredBlock {
                from: start,
                to,
                successors,
                calls: Vec::new(),
            });
        }
        blocks.sort_by_key(|block| block.from);
        Some(Ok(blocks))
    }
    fn lift(&self, function: &FunctionCode) -> Option<Result<LiftedGraph, String>> {
        let index_of = |address: u64| {
            function
                .cfg
                .blocks
                .iter()
                .position(|block| block.from == address)
                .ok_or_else(|| format!("no block at {address:#x}"))
        };
        let mut nodes = Vec::new();
        for block in &function.cfg.blocks {
            let instructions: Vec<&DecodedInsn> = function
                .disasm
                .instructions
                .iter()
                .filter(|ins| ins.address >= block.from && ins.address < block.to)
                .collect();
            let mut statements = Vec::new();
            let mut terminator = Terminator::Return;
            for ins in &instructions {
                match ins.flow {
                    Flow::Call(target) => statements.push(Rewrite::statement(
                        AstNode::Call {
                            callee: Box::new(AstNode::FunctionName {
                                name: format!("sub_{target:x}"),
                                address: target,
                            }),
                            args: Vec::new(),
                        },
                        vec![ins.address],
                    )),
                    Flow::ConditionalBranch(target) => {
                        let Some(next) = block
                            .successor_addresses
                            .iter()
                            .copied()
                            .find(|successor| *successor != target)
                        else {
                            return Some(Err("a branch falls through somewhere".to_string()));
                        };
                        match (index_of(target), index_of(next)) {
                            (Ok(taken), Ok(next)) => {
                                terminator = Terminator::Branch {
                                    cond: AstNode::var("flag"),
                                    taken,
                                    next,
                                    addresses: vec![ins.address],
                                }
                            }
                            (Err(error), _) | (_, Err(error)) => return Some(Err(error)),
                        }
                    }
                    Flow::UnconditionalBranch(target) => match index_of(target) {
                        Ok(target) => {
                            terminator = Terminator::Goto {
                                target,
                                addresses: vec![ins.address],
                            }
                        }
                        Err(error) => return Some(Err(error)),
                    },
                    _ => {}
                }
            }
            nodes.push(Node {
                address: block.from,
                statements,
                terminator,
            });
        }
        Some(Ok(LiftedGraph {
            return_type: "void".to_string(),
            params: Vec::new(),
            locals: vec![ag_engine::lift::Variable {
                ty: "int".to_string(),
                name: "flag".to_string(),
                placements: Vec::new(),
                fragment: None,
            }],
            entry: 0,
            nodes,
            frame: Vec::new(),
        }))
    }
}

#[test]
fn a_plugins_architecture_recovers_its_blocks_and_lifts_its_functions() {
    plugin::register_loader(Arc::new(ToyLoader2));
    plugin::register_architecture(Arc::new(ToyLifting));
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = Scratch(std::env::temp_dir().join(format!(
        "ag-image-lifting-{}-{:?}.toy",
        std::process::id(),
        std::thread::current().id()
    )));
    // 0x100: br 0x104 with its delay slot, the nop at 0x102; 0x103: ret;
    // 0x104: nop; 0x105: ret.
    std::fs::write(&path.0, b"TOY2\x06\x03\x04\x00\x01\x00\x01").unwrap();
    let image = Binary::open(&path.0).expect("the second toy loader reads the file");
    assert_eq!(image.language(), "TOYLIFT:LE:32:default");
    assert_eq!(image.plugin_architecture().as_deref(), Some("toy-lifting"));
    assert!(image.supports_pseudocode());

    // The blocks are the architecture's: the delay slot in the branch's.
    let listing = image.disassembly(0x100).expect("the toy code decodes");
    let ranges: Vec<(u64, u64)> = listing
        .blocks
        .iter()
        .map(|block| (block.from, block.to))
        .collect();
    assert_eq!(ranges, [(0x100, 0x103), (0x103, 0x104), (0x104, 0x106)]);
    let graph = image.control_flow(0x100).expect("a graph");
    assert_eq!(graph.edges.len(), 2);

    // The function is the architecture's lift, structured by the engine.
    let pseudocode = image.pseudocode(0x100).expect("lifted by the architecture");
    let text = pseudocode.text();
    assert!(text.contains("void start("), "{text}");
    assert!(text.contains("int flag"), "{text}");
    assert!(text.contains("if (flag)"), "{text}");

    // The levels: the lifted one by the blocks, the medium one the graph,
    // the high one the body; no low level.
    let lifted = image.il(0x100, Level::Lifted, false).expect("lifted");
    assert_eq!(lifted.blocks.len(), 3);
    assert_eq!(lifted.items.len(), 5);
    assert!(lifted.text().contains("br 0x104"), "{}", lifted.text());
    let low = image.il(0x100, Level::Low, false).expect("low");
    assert!(low.blocks.is_empty());
    let medium = image.il(0x100, Level::Medium, true).expect("medium");
    assert_eq!(medium.blocks.len(), 3);
    assert!(
        medium
            .text()
            .contains("if (flag#0) goto block_104 else goto block_103"),
        "{}",
        medium.text()
    );
    let high = image.il(0x100, Level::High, false).expect("high");
    assert!(high.text().contains("if (flag)"), "{}", high.text());
    assert!(
        high.items
            .iter()
            .any(|item| item.opcode.as_deref() == Some("if")),
        "{}",
        high.text()
    );
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

/// The toy container again, with a third magic, for a language the
/// architecture below only decodes — and a lift hook gives pseudocode.
struct ToyHookLoader;

impl Loader for ToyHookLoader {
    fn name(&self) -> &str {
        "toy-hook-loader"
    }
    fn recognizes(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"TOY3")
    }
    fn load(&self, name: &str, bytes: &[u8]) -> Result<LoadedImage, String> {
        let mut image = ToyLoader.load(name, bytes)?;
        image.language = "TOYHOOK:LE:32:default".to_string();
        Ok(image)
    }
}

/// The toy instruction set, decoding only: it does not lift, so without a
/// hook its image has no pseudocode.
struct ToyHookCpu;

impl Architecture for ToyHookCpu {
    fn name(&self) -> &str {
        "toy-hook-cpu"
    }
    fn languages(&self) -> Vec<String> {
        vec!["TOYHOOK:LE:32:default".to_string()]
    }
    fn bitness(&self, _language: &str) -> Bitness {
        Bitness::Bits32
    }
    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        ToyCpu.decode_section(language, bytes, base)
    }
}

/// A hook that lifts the toy function the architecture only decodes: one
/// call to `hooked`, then a return. It patches the language's lifting
/// without registering an architecture in the decoder's place.
struct ToyLiftHook;

impl LiftHook for ToyLiftHook {
    fn name(&self) -> &str {
        "toy-lift-hook"
    }
    fn languages(&self) -> Vec<String> {
        vec!["TOYHOOK:LE:32:default".to_string()]
    }
    fn patch(
        &self,
        function: &FunctionCode,
        lifted: Option<&Result<LiftedGraph, String>>,
    ) -> Option<Result<LiftedGraph, String>> {
        // The architecture does not lift the language: there is no lift.
        assert!(lifted.is_none());
        assert_eq!(function.language, "TOYHOOK:LE:32:default");
        assert_eq!(function.address, 0x100);
        Some(Ok(LiftedGraph {
            return_type: "void".to_string(),
            params: Vec::new(),
            locals: Vec::new(),
            entry: 0,
            nodes: vec![Node {
                address: 0x100,
                statements: vec![Rewrite::statement(
                    AstNode::Call {
                        callee: Box::new(AstNode::FunctionName {
                            name: "hooked".to_string(),
                            address: 0,
                        }),
                        args: Vec::new(),
                    },
                    vec![0x100],
                )],
                terminator: Terminator::Return,
            }],
            frame: Vec::new(),
        }))
    }
}

#[test]
fn a_lift_hook_gives_pseudocode_to_an_architecture_that_only_decodes() {
    plugin::register_loader(Arc::new(ToyHookLoader));
    plugin::register_architecture(Arc::new(ToyHookCpu));
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = Scratch(std::env::temp_dir().join(format!(
        "ag-image-hook-{}-{:?}.toy",
        std::process::id(),
        std::thread::current().id()
    )));
    // 0x100: nop; 0x101: ret.
    std::fs::write(&path.0, b"TOY3\x02\x00\x01").unwrap();

    // Without the hook the architecture decodes but does not lift.
    let image = Binary::open(&path.0).expect("the third toy loader reads the file");
    assert_eq!(image.language(), "TOYHOOK:LE:32:default");
    assert_eq!(image.plugin_architecture().as_deref(), Some("toy-hook-cpu"));
    assert!(image.supports_disassembly());
    assert!(!image.supports_pseudocode());
    assert!(image.pseudocode(0x100).is_err());

    // The hook patches the language's lifting: the image has pseudocode
    // now, and it is the hook's, structured by the engine.
    plugin::register_lift_hook(Arc::new(ToyLiftHook));
    let image = Binary::open(&path.0).expect("the third toy loader reads the file");
    assert!(image.supports_pseudocode());
    let pseudocode = image.pseudocode(0x100).expect("lifted by the hook");
    let text = pseudocode.text();
    assert!(text.contains("void start("), "{text}");
    assert!(text.contains("hooked()"), "{text}");
    // The medium level is the hook's graph.
    let medium = image.il(0x100, Level::Medium, false).expect("medium");
    assert!(medium.text().contains("hooked()"), "{}", medium.text());
    plugin::unregister_lift_hook("toy-lift-hook");
}

/// A toy container whose architecture lifts every function to the same
/// counted loop, so the engine's structuring — and its `loop-form` option —
/// can be exercised without a real instruction set.
struct ToyLoopLoader;

impl Loader for ToyLoopLoader {
    fn name(&self) -> &str {
        "toy-loop-loader"
    }
    fn recognizes(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"TOYL")
    }
    fn load(&self, name: &str, bytes: &[u8]) -> Result<LoadedImage, String> {
        let mut image = ToyLoader.load(name, bytes)?;
        image.language = "TOYLOOP:LE:32:default".to_string();
        Ok(image)
    }
}

/// Lifts every function to the counted loop of structure.rs's
/// `a_header_that_branches_out_is_a_while_and_a_counted_one_a_for`:
/// `i = 0; for/while (i < 3) { x = 1; i = i + 1; }`. The graph is fixed,
/// independent of the toy code, so the engine structures the same loop
/// under whatever `loop-form` the function is analyzed with.
struct ToyLoop;

impl Architecture for ToyLoop {
    fn name(&self) -> &str {
        "toy-loop"
    }
    fn languages(&self) -> Vec<String> {
        vec!["TOYLOOP:LE:32:default".to_string()]
    }
    fn bitness(&self, _language: &str) -> Bitness {
        Bitness::Bits32
    }
    fn decode_section(
        &self,
        language: &str,
        bytes: &[u8],
        base: u64,
    ) -> Result<DecodedSection, String> {
        ToyCpu.decode_section(language, bytes, base)
    }
    fn lifts(&self, _language: &str) -> bool {
        true
    }
    fn blocks(
        &self,
        _language: &str,
        disasm: &ag_engine::Disasm,
        entry: u64,
    ) -> Option<Result<Vec<RecoveredBlock>, String>> {
        let end = disasm
            .instructions
            .last()
            .map_or(entry, |ins| ins.address + ins.length as u64);
        Some(Ok(vec![RecoveredBlock {
            from: entry,
            to: end,
            successors: Vec::new(),
            calls: Vec::new(),
        }]))
    }
    fn lift(&self, _function: &FunctionCode) -> Option<Result<LiftedGraph, String>> {
        let assign = |name: &str, value: u64, address: u64| {
            Rewrite::statement(
                AstNode::Assign {
                    lhs: Box::new(AstNode::var(name)),
                    rhs: Box::new(AstNode::constant(value, 4)),
                },
                vec![address],
            )
        };
        let step = Rewrite::statement(
            AstNode::Assign {
                lhs: Box::new(AstNode::var("i")),
                rhs: Box::new(AstNode::binary(
                    AstNode::var("i"),
                    BinaryOp::Add,
                    AstNode::constant(1, 4),
                )),
            },
            vec![0x1024],
        );
        let nodes = vec![
            Node {
                address: 0x1000,
                statements: vec![assign("i", 0, 0x1000)],
                terminator: Terminator::Goto {
                    target: 1,
                    addresses: vec![],
                },
            },
            Node {
                address: 0x1010,
                statements: vec![],
                terminator: Terminator::Branch {
                    cond: AstNode::binary(
                        AstNode::var("i"),
                        BinaryOp::GreaterEqual,
                        AstNode::constant(3, 4),
                    ),
                    taken: 3,
                    next: 2,
                    addresses: vec![0x1010, 0x1013],
                },
            },
            Node {
                address: 0x1020,
                statements: vec![assign("x", 1, 0x1020), step],
                terminator: Terminator::Goto {
                    target: 1,
                    addresses: vec![0x1028],
                },
            },
            Node {
                address: 0x1030,
                statements: vec![],
                terminator: Terminator::Return,
            },
        ];
        Some(Ok(LiftedGraph {
            return_type: "void".to_string(),
            params: Vec::new(),
            locals: vec![
                ag_engine::lift::Variable::new("int", "i"),
                ag_engine::lift::Variable::new("int", "x"),
            ],
            entry: 0,
            nodes,
            frame: Vec::new(),
        }))
    }
}

#[test]
fn audit_plugin_stages_cache_ignores_a_per_function_loop_form_option() {
    plugin::register_loader(Arc::new(ToyLoopLoader));
    plugin::register_architecture(Arc::new(ToyLoop));
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = Scratch(std::env::temp_dir().join(format!(
        "ag-image-loop-{}-{:?}.toy",
        std::process::id(),
        std::thread::current().id()
    )));
    // 0x100: nop nop nop ret — the architecture lifts a fixed counted loop
    // regardless of these bytes.
    std::fs::write(&path.0, b"TOYL\x04\x00\x00\x00\x01").unwrap();
    let image = Binary::open(&path.0).expect("the loop toy loader reads the file");
    assert!(image.supports_pseudocode());

    // Control: under the default loop-form=for the counted loop is a for.
    let for_text = image
        .pseudocode(0x100)
        .expect("lifted by the architecture")
        .text()
        .to_string();
    assert!(
        for_text.contains("for ("),
        "control: default loop-form is for: {for_text}"
    );
    assert!(!for_text.contains("while ("), "control: {for_text}");

    // The same function with a per-function loop-form=while option.
    let mut props = FunctionProperties::default();
    props
        .options
        .insert("loop-form".to_string(), "while".to_string());
    assert!(image.set_function_properties(BTreeMap::from([(0x100u64, props)])));
    let while_text = image
        .pseudocode(0x100)
        .expect("lifted again")
        .text()
        .to_string();
    assert!(
        while_text.contains("while ("),
        "per-function loop-form=while must restructure the cached plugin lift; \
         set_function_properties cleared pseudocode but not plugin_stages, so \
         architecture_stages returned the stale for-loop: {while_text}"
    );
}
