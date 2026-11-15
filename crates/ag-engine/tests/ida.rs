//! The IDA reader against python-idb's own test databases (#403). The
//! ground truth here was dumped with python-idb 0.8.0; see the fixtures
//! README for how each database was made and what it holds.

use std::path::Path;

use ag_engine::ida::container;
use ag_engine::ida::extract::{CommentKind, Idb};
use ag_engine::ida::netnode::Netnodes;
use ag_engine::ida::til::Til;

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ida")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn container_func_comment() {
    let db = container::parse(&fixture("func-comment_small.idb")).unwrap();
    assert_eq!(db.wordsize, 4);
    assert_eq!(db.version, 6);
    assert_eq!(db.record_count, 272);
    assert_eq!(db.index.len(), 272, "the walk visits every record once");
    // "$ MAX LINK" is a fixed node every database carries.
    assert_eq!(db.index.get(&b"$ MAX LINK"[..]).unwrap(), &[0, 0, 0, 0]);
}

#[test]
fn container_elf_cat_compressed() {
    // Every section of this one is zlib-compressed: the walk also proves
    // the inflate against real IDA data.
    let db = container::parse(&fixture("elf_cat.i64")).unwrap();
    assert_eq!(db.wordsize, 8);
    assert_eq!(db.version, 6);
    assert_eq!(db.record_count, 12112);
    assert_eq!(db.index.len(), 12112);
    assert_eq!(db.index.get(&b"$ MAX LINK"[..]).unwrap(), &[0; 8]);
    assert!(db.til.is_some(), "elf_cat carries a local type library");
}

#[test]
fn container_empty() {
    let db = container::parse(&fixture("empty_empty.idb")).unwrap();
    assert_eq!(db.wordsize, 4);
    assert_eq!(db.index.len(), db.record_count as usize);
}

#[test]
fn container_rejects_non_ida() {
    assert!(container::parse(b"not an idb file at all").is_err());
    assert!(container::parse(&[]).is_err());
}

#[test]
fn netnode_root() {
    let db = container::parse(&fixture("func-comment_small.idb")).unwrap();
    let nodes = Netnodes::read(&db);
    let root = nodes.by_name("Root Node").expect("Root Node");
    assert_eq!(root.altval(-1), Some(695), "version");
    assert_eq!(root.supstr(1303).as_deref(), Some("6.95"));
    assert_eq!(
        root.value
            .as_deref()
            .map(ag_engine::ida::netnode::string_of),
        Some(
            "Z:\\home\\user\\Documents\\code\\python-idb\\tests\\data\\small\\small.bin"
                .to_string()
        )
    );
    // The md5 is raw 16 bytes; render as hex.
    let md5: String = root
        .sup
        .get(&1302)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(md5, "c897d1410af8f2c74fba11b1db511e9e");
}

#[test]
fn netnode_function_comment() {
    let db = container::parse(&fixture("func-comment_small.idb")).unwrap();
    let nodes = Netnodes::read(&db);
    let funcs = nodes.by_name("$ funcs").expect("$ funcs node");
    // The function at 0x3 carries its comment on the $ funcs node, tag C.
    let comment = funcs
        .char
        .get(&3)
        .map(|bytes| ag_engine::ida::netnode::string_of(bytes));
    assert_eq!(comment.as_deref(), Some("function comment"));
    // Its func_t is the supval at the same index.
    assert!(funcs.sup.contains_key(&3));
}

#[test]
fn extract_func_comment() {
    let idb = Idb::parse(&fixture("func-comment_small.idb")).unwrap();
    let root = idb.root();
    assert_eq!(root.version, 695);
    assert_eq!(root.version_string, "6.95");
    assert_eq!(root.imagebase, 0);
    assert_eq!(root.procname, "metapc");
    assert_eq!(root.filetype, 2);
    assert_eq!(
        root.md5.as_deref(),
        Some("c897d1410af8f2c74fba11b1db511e9e")
    );

    let funcs: Vec<_> = idb
        .functions()
        .into_iter()
        .filter(|f| !f.is_tail())
        .collect();
    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0].start, 0x3);
    assert_eq!(funcs[0].end, 0xd);
    assert_eq!(funcs[0].flags, 0x401);
    assert_eq!(funcs[0].comment.as_deref(), Some("function comment"));
    assert_eq!(
        funcs[0].repeatable_comment.as_deref(),
        Some("repeatable function comment")
    );
}

#[test]
fn extract_anterior_posterior() {
    let idb = Idb::parse(&fixture("ant-post-comments_small.idb")).unwrap();
    let comments = idb.comments();
    let anterior: Vec<_> = comments
        .iter()
        .filter(|c| c.address == 0x1 && c.kind == CommentKind::Anterior)
        .collect();
    let posterior: Vec<_> = comments
        .iter()
        .filter(|c| c.address == 0x1 && c.kind == CommentKind::Posterior)
        .collect();
    assert_eq!(anterior.len(), 2);
    assert_eq!(anterior[0].text, "anterior line 1");
    assert_eq!(anterior[1].text, "anterior line 2");
    assert_eq!(posterior.len(), 2);
    assert_eq!(posterior[0].text, "posterior line 1");
    assert_eq!(posterior[1].text, "posterior line 2");
}

#[test]
fn extract_elf_cat() {
    let idb = Idb::parse(&fixture("elf_cat.i64")).unwrap();
    let root = idb.root();
    assert_eq!(root.version, 700);
    assert_eq!(root.imagebase, 0x400000);
    assert_eq!(root.filetype, 18);
    assert_eq!(root.procname, "metapc");
    assert_eq!(idb.names().len(), 321);
    let entries: Vec<_> = idb
        .functions()
        .into_iter()
        .filter(|f| !f.is_tail())
        .collect();
    assert_eq!(entries.len(), 139);
    let segs = idb.segments();
    assert!(segs
        .iter()
        .any(|s| s.name == ".text" && s.start == 0x401a40));
    assert!(segs.iter().any(|s| s.name == ".bss"));
    // A named data symbol.
    let names = idb.names();
    assert!(names
        .iter()
        .any(|(ea, n)| *ea == 0x400298 && n == "elf_gnu_hash_nbuckets"));
}

#[test]
fn til_empty() {
    let til = Til::parse(&fixture("empty_empty.til")).unwrap();
    assert_eq!(til.format, 18);
    assert_eq!(til.title, "Local type definitions");
    assert_eq!(til.size_i, 4);
    assert_eq!(til.size_e, 4);
    assert!(til.types.is_empty());
    assert!(til.symbols.is_empty());
}

#[test]
fn til_elf_cat_records() {
    let idb = Idb::parse(&fixture("elf_cat.i64")).unwrap();
    let til = Til::parse(idb.til_bytes().unwrap()).unwrap();
    assert_eq!(til.base, "gnulnx_x64");
    assert_eq!(til.types.len(), 21);
    let sym = til.by_name("Elf64_Sym").expect("Elf64_Sym");
    assert_eq!(sym.ordinal, 1);
    assert_eq!(
        sym.fields,
        vec!["st_name", "st_info", "st_other", "st_shndx", "st_value", "st_size"]
    );
    assert!(!sym.type_info.is_empty());
    assert!(til.by_name("Elf64_Rela").is_some());
    assert!(til.by_name("Elf64_Dyn").is_some());
}

#[test]
fn types_render_and_parse() {
    use ag_engine::ida::types;
    use ag_engine::types::DataModel;

    let idb = Idb::parse(&fixture("elf_cat.i64")).unwrap();
    let til = Til::parse(idb.til_bytes().unwrap()).unwrap();
    let model = DataModel::LP64;

    // The renderable types come back in dependency order, and the engine
    // reads them all; C++ classes that are no plain C are held back.
    let definitions = types::render_all(&til, model);
    assert!(
        definitions.len() >= 15,
        "most types render: {}",
        definitions.len()
    );
    let (_store, notes) = ag_engine::ctype::build(model, &definitions)
        .unwrap_or_else(|e| panic!("the rendered types do not parse: {e}"));
    assert!(notes.is_empty(), "notes: {notes:?}");
    for name in ["Elf64_Sym", "Elf64_Rela", "Elf64_Dyn", "stat", "__dev_t"] {
        assert!(
            definitions.iter().any(|d| d.name == name),
            "{name} should render"
        );
    }

    // The Elf64_Sym structure spells its members with the right types.
    let sym = til.by_name("Elf64_Sym").unwrap();
    let c = types::render_record(sym, &til, model).unwrap();
    assert!(c.starts_with("typedef struct Elf64_Sym {"), "{c}");
    assert!(c.contains("uint32_t st_name;"), "{c}");
    assert!(c.contains("uint8_t st_info;"), "{c}");
    assert!(c.contains("uint16_t st_shndx;"), "{c}");
    assert!(c.contains("uint64_t st_value;"), "{c}");
    assert!(c.contains("uint64_t st_size;"), "{c}");

    // A typedef of a primitive.
    let dev = til.by_name("__dev_t").unwrap();
    let c = types::render_record(dev, &til, model).unwrap();
    assert_eq!(c, "typedef uint64_t __dev_t;");
}
