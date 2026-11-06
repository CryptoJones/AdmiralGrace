use std::path::Path;

use ag_engine::Image;

fn cxx() -> Image {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cxx.elf");
    Image::open(&path).expect("the C++ fixture ELF loads")
}

#[test]
fn the_cxx_metadata_names_the_classes_and_their_vtables() {
    let image = cxx();
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    assert!(metadata.classes.contains_key("base"), "{:?}", metadata.classes.keys());
    assert!(metadata.classes.contains_key("derived"), "{:?}", metadata.classes.keys());
    // The ABI's own classes are not classes of the program.
    assert!(
        !metadata.classes.keys().any(|name| name.contains("__cxxabiv1")),
        "{:?}",
        metadata.classes.keys()
    );
    let base = &metadata.classes["base"];
    assert_eq!(base.vtable, Some(0x402048));
    assert_eq!(base.type_info, Some(0x402010));
    let derived = &metadata.classes["derived"];
    assert_eq!(derived.vtable, Some(0x402068));
    assert_eq!(derived.type_info, Some(0x402030));
}

#[test]
fn the_vtables_hold_the_virtual_functions_in_declaration_order() {
    let image = cxx();
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    let base = &metadata.classes["base"];
    let names: Vec<&str> = base.vfuncs.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["base::f(int)", "base::g()"]);
    assert_eq!(base.vfuncs[0].slot, 0);
    assert_eq!(base.vfuncs[1].slot, 1);
    assert!(base.vfuncs.iter().all(|v| v.implementation.is_some()));
    // The derived table overrides the first slot and inherits the second.
    let derived = &metadata.classes["derived"];
    let names: Vec<&str> = derived.vfuncs.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["derived::f(int)", "base::g()"]);
    assert_ne!(derived.vfuncs[0].implementation, base.vfuncs[0].implementation);
    assert_eq!(derived.vfuncs[1].implementation, base.vfuncs[1].implementation);
}

#[test]
fn the_vtable_references_name_the_class_and_the_slot() {
    let image = cxx();
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    // The first slot of each table, by its address in the image.
    assert_eq!(metadata.vtable_refs.get(&0x402058), Some(&("base".to_string(), 0)));
    assert_eq!(metadata.vtable_refs.get(&0x402060), Some(&("base".to_string(), 1)));
    assert_eq!(
        metadata.vtable_refs.get(&0x402078),
        Some(&("derived".to_string(), 0))
    );
    assert_eq!(
        metadata.vtable_refs.get(&0x402080),
        Some(&("derived".to_string(), 1))
    );
    assert_eq!(metadata.vfunc_names.get(&0x401136).map(String::as_str), Some("base::f(int)"));
    assert_eq!(metadata.vfunc_names.get(&0x40113e).map(String::as_str), Some("base::g()"));
    assert_eq!(metadata.vfunc_names.get(&0x401146).map(String::as_str), Some("derived::f(int)"));
}

#[test]
fn the_constructors_are_noted_by_their_address() {
    let image = cxx();
    let metadata = image.cxx().expect("the fixture carries C++ classes");
    let base = &metadata.classes["base"];
    assert_eq!(base.constructor, Some(0x40114e));
    let derived = &metadata.classes["derived"];
    assert_eq!(derived.constructor, Some(0x401162));
}

#[test]
fn the_cxx_references_invert_the_vtable_refs() {
    let image = cxx();
    let references = image.cxx_references().expect("the fixture carries C++ classes");
    assert_eq!(
        references.vtable_refs.get(&0x402058),
        Some(&("base".to_string(), 0))
    );
    // Each vtable stands with its own slots.
    assert_eq!(
        references.vtable_users.get(&0x402048),
        Some(&vec![0x402058, 0x402060])
    );
    assert_eq!(
        references.vtable_users.get(&0x402068),
        Some(&vec![0x402078, 0x402080])
    );
    assert_eq!(
        references.vfunc_names.get(&0x401136).map(String::as_str),
        Some("base::f(int)")
    );
}

#[test]
fn a_c_image_has_no_cxx_classes() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.elf");
    let image = Image::open(&path).expect("the sample ELF loads");
    assert!(image.cxx().is_none());
    assert!(image.cxx_references().is_none());
}
