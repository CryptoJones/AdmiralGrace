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
    assert_eq!(
        ag_engine::image::raw_arch("ARM:LE:32:Cortex:default"),
        Some("thumb")
    );
    assert_eq!(
        ag_engine::image::raw_arch("x86:LE:64:default:gcc"),
        Some("x86-64")
    );
    assert_eq!(ag_engine::image::raw_arch("x86:LE:64:default:clang"), None);

    // Nowhere to load: address 0, no bytes, or past a 32-bit program's space.
    for (spec, says) in [
        (
            RawSpec {
                base: 0,
                ..spec.clone()
            },
            "address 0",
        ),
        (
            RawSpec {
                length: Some(0),
                ..spec.clone()
            },
            "no bytes",
        ),
        (
            RawSpec {
                language: raw_language("x86").unwrap().to_string(),
                base: 0xffff_ff80,
                length: Some(0x100),
                entry: None,
                ..spec.clone()
            },
            "past the top",
        ),
        (
            RawSpec {
                base: 0xffff_ffff_ffff_ff00,
                length: Some(0x100),
                entry: None,
                ..spec.clone()
            },
            "past the top",
        ),
    ] {
        let refused = Image::open_raw(&path, &spec).expect_err(says).to_string();
        assert!(refused.contains(says), "{refused}");
    }
}

#[test]
fn a_universal_macho_names_its_slices_and_opens_as_the_one_chosen() {
    use ag_engine::image::{fat_slices, Image};

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-image/tests/fixtures/sample_fat.macho");
    let bytes = std::fs::read(&path).expect("the fixture");
    let slices = fat_slices(&bytes).expect("a universal Mach-O");
    let arches: Vec<&str> = slices.iter().map(|slice| slice.arch.as_str()).collect();
    assert_eq!(arches, ["x86_64", "arm64"]);
    assert_eq!(slices[0].offset, 0x4000);
    assert_eq!(slices[1].offset, 0x8000);

    // Opened as a plain image, it says what it is and what to choose.
    let refused = Image::open(&path).expect_err("several images").to_string();
    assert!(refused.contains("universal Mach-O"), "{refused}");
    assert!(refused.contains("x86_64, arm64"), "{refused}");

    // Each slice is an image of its own, by name or by number; the bytes
    // the slice holds are the thin image's.
    let x86 = Image::open_slice(&path, "x86_64").expect("the x86-64 slice");
    assert!(
        x86.language().starts_with("x86:LE:64"),
        "{}",
        x86.language()
    );
    assert_eq!(x86.slice().map(|slice| slice.offset), Some(0x4000));
    let arm64 = Image::open_slice(&path, "1").expect("the arm64 slice");
    assert!(
        arm64.language().starts_with("AARCH64:LE:64"),
        "{}",
        arm64.language()
    );
    assert!(arm64.entry().is_some());
    let thin = Image::open(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ag-image/tests/fixtures/sample.macho"),
    )
    .expect("the thin Mach-O");
    assert_eq!(x86.sections().len(), thin.sections().len());
    assert_eq!(x86.function_symbols(), thin.function_symbols());

    // A slice that is not there, and a file that has none.
    let refused = Image::open_slice(&path, "ppc")
        .expect_err("no such slice")
        .to_string();
    assert!(refused.contains("has no slice"), "{refused}");
    assert!(refused.contains("0: x86_64, 1: arm64"), "{refused}");
    let elf = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.elf");
    let refused = Image::open_slice(&elf, "x86_64")
        .expect_err("not universal")
        .to_string();
    assert!(refused.contains("not a universal Mach-O"), "{refused}");
    assert!(fat_slices(&std::fs::read(&elf).unwrap()).is_none());
}

#[test]
fn a_64_bit_fat_header_a_slice_past_the_end_and_a_haswell_slice_are_read() {
    use ag_engine::image::{fat_slices, resolve_slice, Image};

    // A fat64 header over the fixture's two slices: the same slices.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-image/tests/fixtures/sample_fat.macho");
    let fixture = std::fs::read(&path).expect("the fixture");
    let slices = fat_slices(&fixture).expect("universal");
    let mut fat64 = Vec::new();
    fat64.extend_from_slice(&0xcafe_babf_u32.to_be_bytes());
    fat64.extend_from_slice(&(slices.len() as u32).to_be_bytes());
    let cputypes = [(0x0100_0007_u32, 0x8_u32), (0x0100_000c_u32, 0_u32)];
    for (slice, (cputype, cpusubtype)) in slices.iter().zip(cputypes) {
        fat64.extend_from_slice(&cputype.to_be_bytes());
        fat64.extend_from_slice(&cpusubtype.to_be_bytes());
        fat64.extend_from_slice(&slice.offset.to_be_bytes());
        fat64.extend_from_slice(&slice.size.to_be_bytes());
        fat64.extend_from_slice(&14_u32.to_be_bytes());
        fat64.extend_from_slice(&0_u32.to_be_bytes());
    }
    fat64.resize(fixture.len(), 0);
    fat64[0x4000..].copy_from_slice(&fixture[0x4000..]);
    let read = fat_slices(&fat64).expect("a fat64 header");
    assert_eq!(
        read.iter()
            .map(|slice| slice.arch.as_str())
            .collect::<Vec<_>>(),
        ["x86_64h", "arm64"]
    );
    assert_eq!(read[1].offset, slices[1].offset);
    assert_eq!(
        resolve_slice(&read, "ARM64").map(|slice| slice.offset),
        Some(0x8000)
    );
    assert_eq!(
        resolve_slice(&read, "1").map(|slice| slice.offset),
        Some(0x8000)
    );
    assert!(resolve_slice(&read, "5").is_none());
    assert!(
        resolve_slice(&read, "x86_64").is_none(),
        "the Haswell slice has its own name"
    );

    // A slice that runs past the end of the file is refused by name.
    let dir = std::env::temp_dir().join(format!(
        "ag-engine-fat-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let truncated = dir.join("truncated.macho");
    std::fs::write(&truncated, &fixture[..0x8100]).unwrap();
    let refused = Image::open_slice(&truncated, "arm64")
        .expect_err("past the end")
        .to_string();
    assert!(
        refused.contains("runs past the end of the file"),
        "{refused}"
    );
    assert!(Image::open_slice(&truncated, "x86_64").is_ok());

    // A crafted entry at the very top of the space is refused, not overflowed.
    let mut crafted = fat64.clone();
    crafted[8 + 8..8 + 16].copy_from_slice(&0xffff_ffff_ffff_fff0_u64.to_be_bytes());
    crafted[8 + 16..8 + 24].copy_from_slice(&0x100_u64.to_be_bytes());
    let evil = dir.join("evil.macho");
    std::fs::write(&evil, &crafted).unwrap();
    let refused = Image::open_slice(&evil, "0")
        .expect_err("past the end")
        .to_string();
    assert!(
        refused.contains("runs past the end of the file"),
        "{refused}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
