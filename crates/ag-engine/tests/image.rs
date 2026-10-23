use std::path::Path;

use ag_engine::cfgwalk::resolve_branches;
use ag_engine::cpu_context::X86IcedContext;
use ag_engine::pipeline::Disasm;
use ag_engine::Image;

fn sample() -> Image {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.elf");
    Image::open(&path).expect("the sample ELF loads")
}

#[test]
fn the_loader_reads_the_sample_elf() {
    let image = sample();
    assert!(
        image.language().starts_with("x86:LE:64"),
        "{}",
        image.language()
    );
    assert_eq!(image.entry(), Some(0x1060));

    let text = image
        .sections()
        .into_iter()
        .find(|s| s.name == ".text")
        .expect("a .text section");
    assert!(text.executable);
    assert_eq!(text.vma, 0x1060);

    let rodata = image
        .sections()
        .into_iter()
        .find(|s| s.name == ".rodata")
        .expect("a .rodata section");
    assert!(!rodata.executable);

    assert_eq!(image.function_name(0x1198).as_deref(), Some("main"));
    assert_eq!(image.function_name(0x1149).as_deref(), Some("add"));
    assert_eq!(image.function_name(0x1161).as_deref(), Some("sum_to"));
}

#[test]
fn the_code_section_decodes_into_a_cfg_with_named_callees() {
    let image = sample();
    let (text, bytes) = image
        .section_bytes(0x1198)
        .expect("main is in a code section");
    assert_eq!(text.name, ".text");

    let mut ctx = X86IcedContext::default();
    let disasm = Disasm::decode(&mut ctx, bytes, text.vma).expect("the text decodes");
    let cfg = resolve_branches(&disasm, 0x1198);

    assert!(cfg.index_by_address.contains_key(&0x1198));
    let callees: Vec<String> = cfg
        .call_targets
        .iter()
        .filter_map(|&target| image.function_name(target))
        .collect();
    assert!(callees.contains(&"add".to_string()), "{callees:?}");
    assert!(callees.contains(&"sum_to".to_string()), "{callees:?}");
}

#[test]
fn bytes_outside_every_section_are_none() {
    let image = sample();
    assert!(image.bytes_from(0xdead_0000).is_none());
    assert!(image.section_bytes(0xdead_0000).is_none());
}
