//! Loading one image at a time out of a dyld shared cache (#416).
//!
//! The fixture `sample_dyld.cache` is `sample.macho` wrapped twice by
//! `make_dyld_cache.py`, as `/usr/lib/libsample.dylib` at its own addresses
//! and `/usr/lib/libother.dylib` moved up 256 MiB. The first image extracts
//! back to the very bytes of `sample.macho`; the second keeps the same code
//! at the moved addresses.

use std::path::{Path, PathBuf};

use ag_image::Binary;

fn cache_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample_dyld.cache")
}

fn macho_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.macho")
}

#[test]
fn the_cache_lists_its_images() {
    let images = Binary::dyld_images_of(&cache_path())
        .expect("the cache reads")
        .expect("the file is a cache");
    assert_eq!(images.len(), 2);
    assert_eq!(images[0].path, "/usr/lib/libsample.dylib");
    assert_eq!(images[0].address, 0x100000000);
    assert_eq!(images[1].path, "/usr/lib/libother.dylib");
    assert_eq!(images[1].address, 0x110000000);
}

#[test]
fn a_plain_file_is_not_a_cache() {
    assert!(Binary::dyld_images_of(&macho_path())
        .expect("the Mach-O reads")
        .is_none());
}

#[test]
fn opening_the_cache_whole_is_refused() {
    let error = Binary::open(&cache_path()).expect_err("a cache is many images, not one");
    let message = format!("{error:#}");
    assert!(message.contains("dyld shared cache"), "{message}");
    assert!(message.contains("--dyld-image"), "{message}");
}

#[test]
fn one_image_is_lifted_out_by_its_basename() {
    let binary = Binary::open_dyld_with_layout(
        &cache_path(),
        "libsample.dylib",
        &ag_image::Layout::default(),
    )
    .expect("the image lifts out");

    assert!(
        binary.language().starts_with("x86:LE:64"),
        "{}",
        binary.language()
    );
    assert_eq!(binary.entry(), Some(0x100000440));
    let text = binary
        .sections()
        .iter()
        .find(|section| section.name == "__text")
        .expect("a __text section");
    assert!(text.executable);
    assert_eq!(text.vma, 0x100000420);
    assert_eq!(binary.function_name(0x100000420), Some("_add"));
    assert_eq!(binary.function_name(0x100000440), Some("_main"));

    let dyld = binary.dyld_image().expect("the image remembers its cache");
    assert_eq!(dyld.path, "/usr/lib/libsample.dylib");
    assert_eq!(dyld.address, 0x100000000);
}

#[test]
fn the_first_image_extracts_to_the_original_bytes() {
    // The first image keeps sample.macho's own addresses, so lifting it out
    // reverses the wrapping exactly: the extracted file is the fixture.
    let image =
        ag_engine::Image::open_dyld(&cache_path(), "0").expect("the image lifts out by position");
    let original = std::fs::read(macho_path()).expect("the Mach-O fixture reads");
    assert_eq!(image.file_bytes(), original.as_slice());
}

#[test]
fn the_second_image_keeps_its_code_at_the_moved_addresses() {
    let binary = Binary::open_dyld_with_layout(
        &cache_path(),
        "/usr/lib/libother.dylib",
        &ag_image::Layout::default(),
    )
    .expect("the second image lifts out by full path");
    assert_eq!(binary.entry(), Some(0x110000440));
    assert_eq!(binary.function_name(0x110000420), Some("_add"));
    assert_eq!(binary.function_name(0x110000440), Some("_main"));

    let disassembly = binary.disassembly(0x110000440).expect("main decodes");
    let calls: Vec<u64> = disassembly.calls.iter().map(|call| call.target).collect();
    assert!(calls.contains(&0x110000420), "main calls add: {calls:?}");
}

#[test]
fn an_image_the_cache_does_not_hold_is_refused() {
    let error = Binary::open_dyld_with_layout(
        &cache_path(),
        "libmissing.dylib",
        &ag_image::Layout::default(),
    )
    .expect_err("a name the cache lacks lifts nothing");
    let message = format!("{error:#}");
    assert!(message.contains("libmissing.dylib"), "{message}");
}

#[test]
fn lifting_from_a_plain_file_is_refused() {
    let error = Binary::open_dyld_with_layout(&macho_path(), "0", &ag_image::Layout::default())
        .expect_err("a plain Mach-O is not a cache");
    let message = format!("{error:#}");
    assert!(message.contains("not a dyld shared cache"), "{message}");
}
