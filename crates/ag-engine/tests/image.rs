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
fn the_import_slots_are_the_got_entries_the_dynamic_relocations_name() {
    let image = sample();
    let slots = image.import_slots();
    assert_eq!(
        slots,
        vec![
            (0x3fd0, "printf".to_string()),
            (0x3fd8, "__libc_start_main".to_string()),
            (0x3fe0, "_ITM_deregisterTMCloneTable".to_string()),
            (0x3fe8, "__gmon_start__".to_string()),
            (0x3ff0, "_ITM_registerTMCloneTable".to_string()),
            (0x3ff8, "__cxa_finalize".to_string()),
        ],
        "the JUMP_SLOT of printf and the GLOB_DATs, by slot, the versions stripped"
    );
}

#[test]
fn bytes_outside_every_section_are_none() {
    let image = sample();
    assert!(image.bytes_from(0xdead_0000).is_none());
    assert!(image.section_bytes(0xdead_0000).is_none());
}

#[test]
fn raw_bytes_load_where_the_analyst_says_as_one_section_of_code() {
    use ag_engine::image::{raw_language, Image, RawSpec};

    // The sample ELF's `.text`, read as raw bytes from its file offset, at
    // its own address: the same bytes the loader finds.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.elf");
    let spec = RawSpec {
        language: raw_language("x86-64")
            .expect("a known architecture")
            .to_string(),
        base: 0x1060,
        entry: Some(0x1149),
        offset: 0x1060,
        length: Some(0x18c),
    };
    let raw = Image::open_raw(&path, &spec).expect("raw bytes load");
    assert_eq!(raw.language(), "x86:LE:64:default:gcc");
    assert_eq!(raw.entry(), Some(0x1149));
    let sections = raw.sections();
    assert_eq!(sections.len(), 1);
    assert_eq!(
        (sections[0].vma, sections[0].size, sections[0].executable),
        (0x1060, 0x18c, true)
    );
    assert_eq!(raw.executable_ranges(), vec![(0x1060, 0x18c)]);
    assert!(raw.function_symbols().is_empty());
    assert!(raw.import_slots().is_empty());
    assert_eq!(raw.load_base(), Some(0x1060));
    let loaded = Image::open(&path).expect("the ELF loads");
    assert_eq!(raw.bytes_from(0x1149), loaded.bytes_from(0x1149));
    assert_eq!(raw.raw().and_then(|spec| spec.length), Some(0x18c));

    // The rest of the file, when no length is said; and what does not fit.
    let rest = Image::open_raw(
        &path,
        &RawSpec {
            length: None,
            ..spec.clone()
        },
    )
    .expect("loads");
    assert_eq!(
        rest.sections()[0].size,
        std::fs::metadata(&path).unwrap().len() - 0x1060
    );
    let refused = Image::open_raw(
        &path,
        &RawSpec {
            offset: 0x1_0000_0000,
            ..spec.clone()
        },
    )
    .expect_err("past the end")
    .to_string();
    assert!(refused.contains("past the end"), "{refused}");
    let refused = Image::open_raw(
        &path,
        &RawSpec {
            entry: Some(0x10),
            ..spec.clone()
        },
    )
    .expect_err("outside")
    .to_string();
    assert!(refused.contains("outside the bytes"), "{refused}");

    // Raw Thumb firmware: the entry's low bit is the one mode hint.
    let thumb = Image::open_raw(
        &path,
        &RawSpec {
            language: raw_language("thumb").unwrap().to_string(),
            entry: Some(0x1061),
            ..spec.clone()
        },
    )
    .expect("loads");
    assert_eq!(thumb.arm_mode_hints(), vec![(0x1060, true)]);
    assert_eq!(raw_language("sparc"), None);
}
