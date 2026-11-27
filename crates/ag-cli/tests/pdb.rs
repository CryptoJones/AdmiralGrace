//! End-to-end tests for `ag pdb` (`info`, `fetch`, `apply`) (#400).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

fn stem(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ag-cli-pdb-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

fn ag(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(args)
        .output()
        .expect("ag binary runs");
    assert!(
        output.status.success(),
        "ag {args:?} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn minimal_pe64_with_rsds(guid: [u8; 16], age: u32, pdb_path: &str) -> Vec<u8> {
    let mut pe = vec![0u8; 0x600];
    pe[0] = b'M';
    pe[1] = b'Z';
    let pe_off = 0x80usize;
    pe[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let coff = pe_off + 4;
    pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
    pe[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

    let opt = coff + 20;
    pe[opt..opt + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    pe[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    pe[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    pe[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
    pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

    let debug_dir_rva = 0x1020u32;
    let debug_dir_raw = 0x220usize;
    pe[opt + 160..opt + 164].copy_from_slice(&debug_dir_rva.to_le_bytes());
    pe[opt + 164..opt + 168].copy_from_slice(&28u32.to_le_bytes());

    let sec = opt + 240;
    pe[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    pe[sec + 8..sec + 12].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[sec + 16..sec + 20].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // Function at 0x140001000: `push rbp; mov rbp, rsp; sub rsp, 0x20; mov eax, [rbp-0x10]; leave; ret`
    let code = [
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x8b, 0x45, 0xf0, 0xc9, 0xc3,
    ];
    pe[0x200..0x200 + code.len()].copy_from_slice(&code);

    let rsds_raw = 0x260usize;
    let rsds_rva = 0x1060u32;
    let mut rsds = b"RSDS".to_vec();
    rsds.extend_from_slice(&guid);
    rsds.extend_from_slice(&age.to_le_bytes());
    rsds.extend_from_slice(pdb_path.as_bytes());
    rsds.push(0);
    pe[rsds_raw..rsds_raw + rsds.len()].copy_from_slice(&rsds);

    pe[debug_dir_raw + 12..debug_dir_raw + 16].copy_from_slice(&2u32.to_le_bytes());
    pe[debug_dir_raw + 16..debug_dir_raw + 20]
        .copy_from_slice(&(rsds.len() as u32).to_le_bytes());
    pe[debug_dir_raw + 20..debug_dir_raw + 24].copy_from_slice(&rsds_rva.to_le_bytes());
    pe[debug_dir_raw + 24..debug_dir_raw + 28].copy_from_slice(&(rsds_raw as u32).to_le_bytes());

    pe
}

fn build_pdb_bytes(guid: [u8; 16], age: u32) -> Vec<u8> {
    // Use the exact MSF/PDB fixture helper built in ag-engine's test module.
    // Reconstruct a minimal valid PDB using raw records:
    let mut streams: Vec<Vec<u8>> = Vec::new();
    let _ = &mut streams;
    // Actually call the helper in engine_pdb_helpers via a small wrapper?
    // Wait: functions in `engine_pdb_helpers` are private, so let's keep a
    // compact self-contained builder here or expose nothing outside tests.
    mini_pdb(guid, age)
}

fn mini_pdb(guid: [u8; 16], age: u32) -> Vec<u8> {
    // Types:
    // 0x1000: FieldList { int32 x; int32 y; }
    // 0x1001: Struct Point (size 8)
    // 0x1002: ArgList [int32, int32]
    // 0x1003: Procedure int32(int32, int32)
    let mut fl = 0x1203u16.to_le_bytes().to_vec();
    for (off, name) in [(0u16, "x"), (4u16, "y")] {
        fl.extend_from_slice(&0x150du16.to_le_bytes());
        fl.extend_from_slice(&3u16.to_le_bytes());
        fl.extend_from_slice(&0x0074u32.to_le_bytes());
        fl.extend_from_slice(&off.to_le_bytes());
        fl.extend_from_slice(name.as_bytes());
        fl.push(0);
        while fl.len() % 4 != 0 {
            fl.push(0xf1);
        }
    }
    let mut st = 0x1505u16.to_le_bytes().to_vec();
    st.extend_from_slice(&2u16.to_le_bytes());
    st.extend_from_slice(&0u16.to_le_bytes());
    st.extend_from_slice(&0x1000u32.to_le_bytes());
    st.extend_from_slice(&0u32.to_le_bytes());
    st.extend_from_slice(&0u32.to_le_bytes());
    st.extend_from_slice(&8u16.to_le_bytes());
    st.extend_from_slice(b"Point\0");

    let mut al = 0x1201u16.to_le_bytes().to_vec();
    al.extend_from_slice(&2u32.to_le_bytes());
    al.extend_from_slice(&0x0074u32.to_le_bytes());
    al.extend_from_slice(&0x0074u32.to_le_bytes());

    let mut pr = 0x1008u16.to_le_bytes().to_vec();
    pr.extend_from_slice(&0x0074u32.to_le_bytes());
    pr.push(0);
    pr.push(0);
    pr.extend_from_slice(&2u16.to_le_bytes());
    pr.extend_from_slice(&0x1002u32.to_le_bytes());

    let type_recs = [fl, st, al, pr];
    let mut tpi_body = Vec::new();
    for r in &type_recs {
        tpi_body.extend_from_slice(&(r.len() as u16).to_le_bytes());
        tpi_body.extend_from_slice(r);
    }
    let mut tpi = Vec::new();
    tpi.extend_from_slice(&20040203u32.to_le_bytes());
    tpi.extend_from_slice(&56u32.to_le_bytes());
    tpi.extend_from_slice(&0x1000u32.to_le_bytes());
    tpi.extend_from_slice(&0x1004u32.to_le_bytes());
    tpi.extend_from_slice(&(tpi_body.len() as u32).to_le_bytes());
    tpi.extend_from_slice(&0xffffu16.to_le_bytes());
    tpi.extend_from_slice(&0xffffu16.to_le_bytes());
    tpi.resize(56, 0);
    tpi.extend_from_slice(&tpi_body);

    // Module symbols: S_GPROC32 `compute` @ sec 1 off 0 (RVA 0x1000), params `a` `b`, regrel32 `sum` [rbp-0x10], register `tmp` rbx
    let mut mod_syms = 4u32.to_le_bytes().to_vec();
    let push_rec = |dst: &mut Vec<u8>, rec: Vec<u8>| {
        dst.extend_from_slice(&(rec.len() as u16).to_le_bytes());
        dst.extend_from_slice(&rec);
    };

    let mut gp = 0x1110u16.to_le_bytes().to_vec();
    gp.extend_from_slice(&[0u8; 12]);
    gp.extend_from_slice(&13u32.to_le_bytes());
    gp.extend_from_slice(&0u32.to_le_bytes());
    gp.extend_from_slice(&13u32.to_le_bytes());
    gp.extend_from_slice(&0x1003u32.to_le_bytes());
    gp.extend_from_slice(&0u32.to_le_bytes());
    gp.extend_from_slice(&1u16.to_le_bytes());
    gp.push(0);
    gp.extend_from_slice(b"compute\0");
    push_rec(&mut mod_syms, gp);

    for p in ["a", "b"] {
        let mut loc = 0x113eu16.to_le_bytes().to_vec();
        loc.extend_from_slice(&0x0074u32.to_le_bytes());
        loc.extend_from_slice(&1u16.to_le_bytes());
        loc.extend_from_slice(p.as_bytes());
        loc.push(0);
        push_rec(&mut mod_syms, loc);
    }

    let mut rr = 0x1111u16.to_le_bytes().to_vec();
    rr.extend_from_slice(&(-0x10i32).to_le_bytes());
    rr.extend_from_slice(&0x0074u32.to_le_bytes());
    rr.extend_from_slice(&334u16.to_le_bytes()); // rbp
    rr.extend_from_slice(b"sum\0");
    push_rec(&mut mod_syms, rr);

    let mut rv = 0x1106u16.to_le_bytes().to_vec();
    rv.extend_from_slice(&0x0074u32.to_le_bytes());
    rv.extend_from_slice(&329u16.to_le_bytes()); // rbx
    rv.extend_from_slice(b"tmp\0");
    push_rec(&mut mod_syms, rv);

    push_rec(&mut mod_syms, 0x0006u16.to_le_bytes().to_vec());

    // Global symbols: S_GDATA32 `g_flag` @ sec 1 off 0x10 (RVA 0x1010)
    let mut globals = Vec::new();
    let mut gd = 0x110du16.to_le_bytes().to_vec();
    gd.extend_from_slice(&0x0074u32.to_le_bytes());
    gd.extend_from_slice(&0x10u32.to_le_bytes());
    gd.extend_from_slice(&1u16.to_le_bytes());
    gd.extend_from_slice(b"g_flag\0");
    push_rec(&mut globals, gd);

    // PDBI
    let mut pdbi = Vec::new();
    pdbi.extend_from_slice(&20000404u32.to_le_bytes());
    pdbi.extend_from_slice(&1u32.to_le_bytes());
    pdbi.extend_from_slice(&age.to_le_bytes());
    pdbi.extend_from_slice(&guid);
    pdbi.extend_from_slice(&0u32.to_le_bytes());
    pdbi.extend_from_slice(&0u32.to_le_bytes());
    pdbi.extend_from_slice(&1u32.to_le_bytes());
    pdbi.extend_from_slice(&0u32.to_le_bytes());
    pdbi.extend_from_slice(&0u32.to_le_bytes());

    // Section header .text @ RVA 0x1000
    let mut sec_hdr = [0u8; 40];
    sec_hdr[..8].copy_from_slice(b".text\0\0\0");
    sec_hdr[8..12].copy_from_slice(&0x400u32.to_le_bytes());
    sec_hdr[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
    sec_hdr[16..20].copy_from_slice(&0x400u32.to_le_bytes());
    sec_hdr[36..40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // DBI
    let mut mod_info = Vec::new();
    mod_info.extend_from_slice(&0u32.to_le_bytes());
    mod_info.extend_from_slice(&1u16.to_le_bytes());
    mod_info.extend_from_slice(&0u16.to_le_bytes());
    mod_info.extend_from_slice(&0u32.to_le_bytes());
    mod_info.extend_from_slice(&0x100u32.to_le_bytes());
    mod_info.extend_from_slice(&0x6000_0020u32.to_le_bytes());
    mod_info.extend_from_slice(&[0u8; 14]);
    mod_info.extend_from_slice(&8u16.to_le_bytes()); // stream 8
    mod_info.extend_from_slice(&(mod_syms.len() as u32).to_le_bytes());
    mod_info.extend_from_slice(&[0u8; 24]);
    mod_info.extend_from_slice(b"m.obj\0m.obj\0");
    while mod_info.len() % 4 != 0 {
        mod_info.push(0);
    }
    let mut dbg_hdr = Vec::new();
    for i in 0..11u16 {
        let v = if i == 5 { 7u16 } else { 0xffff };
        dbg_hdr.extend_from_slice(&v.to_le_bytes());
    }
    let mut dbi = Vec::new();
    dbi.extend_from_slice(&u32::MAX.to_le_bytes());
    dbi.extend_from_slice(&1999_09_03u32.to_le_bytes());
    dbi.extend_from_slice(&age.to_le_bytes());
    dbi.extend_from_slice(&0xffffu16.to_le_bytes());
    dbi.extend_from_slice(&0u16.to_le_bytes());
    dbi.extend_from_slice(&0xffffu16.to_le_bytes());
    dbi.extend_from_slice(&0u16.to_le_bytes());
    dbi.extend_from_slice(&6u16.to_le_bytes()); // globals = stream 6
    dbi.extend_from_slice(&0u16.to_le_bytes());
    dbi.extend_from_slice(&(mod_info.len() as u32).to_le_bytes());
    dbi.extend_from_slice(&[0u8; 20]);
    dbi.extend_from_slice(&(dbg_hdr.len() as u32).to_le_bytes());
    dbi.extend_from_slice(&0u32.to_le_bytes());
    dbi.extend_from_slice(&0u16.to_le_bytes());
    dbi.extend_from_slice(&0x8664u16.to_le_bytes());
    dbi.extend_from_slice(&0u32.to_le_bytes());
    dbi.extend_from_slice(&mod_info);
    dbi.extend_from_slice(&dbg_hdr);

    let streams = vec![
        Vec::new(),
        pdbi,
        tpi,
        dbi,
        Vec::new(),
        Vec::new(),
        globals,
        sec_hdr.to_vec(),
        mod_syms,
    ];
    pack_msf(&streams, 4096)
}

fn pack_msf(streams: &[Vec<u8>], page_size: usize) -> Vec<u8> {
    let pages_needed = |n: usize| n.div_ceil(page_size);
    let mut next = 1usize;
    let mut stream_pages = Vec::new();
    for s in streams {
        let n = pages_needed(s.len());
        stream_pages.push((next..next + n).map(|p| p as u32).collect::<Vec<_>>());
        next += n;
    }
    let mut dir = (streams.len() as u32).to_le_bytes().to_vec();
    for s in streams {
        dir.extend_from_slice(&(s.len() as u32).to_le_bytes());
    }
    for pages in &stream_pages {
        for p in pages {
            dir.extend_from_slice(&p.to_le_bytes());
        }
    }
    let dir_pages: Vec<u32> = (next..next + pages_needed(dir.len()))
        .map(|p| p as u32)
        .collect();
    next += dir_pages.len();
    let list_page = next as u32;
    next += 1;

    let mut file = vec![0u8; next * page_size];
    file[..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00");
    file[32..36].copy_from_slice(&(page_size as u32).to_le_bytes());
    file[36..40].copy_from_slice(&1u32.to_le_bytes());
    file[40..44].copy_from_slice(&(next as u32).to_le_bytes());
    file[44..48].copy_from_slice(&(dir.len() as u32).to_le_bytes());
    file[52..56].copy_from_slice(&list_page.to_le_bytes());

    for (s, pages) in streams.iter().zip(&stream_pages) {
        for (i, p) in pages.iter().enumerate() {
            let chunk = &s[i * page_size..(i * page_size + page_size).min(s.len())];
            let at = *p as usize * page_size;
            file[at..at + chunk.len()].copy_from_slice(chunk);
        }
    }
    for (i, p) in dir_pages.iter().enumerate() {
        let chunk = &dir[i * page_size..(i * page_size + page_size).min(dir.len())];
        let at = *p as usize * page_size;
        file[at..at + chunk.len()].copy_from_slice(chunk);
    }
    let mut list = Vec::new();
    for p in &dir_pages {
        list.extend_from_slice(&p.to_le_bytes());
    }
    let at = list_page as usize * page_size;
    file[at..at + list.len()].copy_from_slice(&list);
    file
}

fn project_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).expect("project file");
    serde_json::from_str(&text).expect("project JSON")
}

#[test]
fn pdb_info_reports_pdb_and_pe_codeview() {
    let dir = stem("info");
    std::fs::create_dir_all(&dir).unwrap();
    let guid = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    let pdb_path = dir.join("prog.pdb");
    let exe_path = dir.join("prog.exe");
    std::fs::write(&pdb_path, build_pdb_bytes(guid, 1)).unwrap();
    std::fs::write(
        &exe_path,
        minimal_pe64_with_rsds(guid, 1, r"C:\build\prog.pdb"),
    )
    .unwrap();

    let out = ag(&[
        "pdb",
        "info",
        pdb_path.to_str().unwrap(),
        "--base",
        "0x140000000",
        "--list",
        "--json",
    ]);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["kind"], "pdb");
    assert_eq!(json["functions"][0]["name"], "compute");
    assert_eq!(json["functions"][0]["address"], "0x140001000");
    assert_eq!(
        json["functions"][0]["prototype"],
        "int32_t compute(int32_t a, int32_t b)"
    );
    assert_eq!(json["functions"][0]["locals"].as_array().unwrap().len(), 2);
    assert_eq!(json["data"][0]["name"], "g_flag");
    assert_eq!(json["data"][0]["address"], "0x140001010");

    let pe_out = ag(&["pdb", "info", exe_path.to_str().unwrap(), "--json"]);
    let pe_json: serde_json::Value = serde_json::from_str(&pe_out).unwrap();
    assert_eq!(pe_json["kind"], "pe");
    assert_eq!(pe_json["codeview"]["filename"], "prog.pdb");
    assert_eq!(
        pe_json["codeview"]["id"],
        "0403020106050807090A0B0C0D0E0F101"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pdb_fetch_and_apply_download_from_symbol_server_and_preserve_analyst_edits() {
    let dir = stem("fetch-apply");
    std::fs::create_dir_all(&dir).unwrap();
    let cache_dir = dir.join("symcache");
    let exe_path = dir.join("app.exe");
    let proj_path = dir.join("app.agproj");
    let guid = [
        0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa,
        0xbb,
    ];
    std::fs::write(
        &exe_path,
        minimal_pe64_with_rsds(guid, 1, r"C:\ci\app.pdb"),
    )
    .unwrap();
    let pdb_bytes = Arc::new(build_pdb_bytes(guid, 1));
    let expected_req = "/app.pdb/DDCCBBAA22114433556677889900AABB1/app.pdb";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pdb_srv = Arc::clone(&pdb_bytes);
    let srv = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            if req.starts_with(&format!("GET {expected_req} ")) {
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    pdb_srv.len()
                );
                stream.write_all(hdr.as_bytes()).unwrap();
                stream.write_all(&pdb_srv).unwrap();
            } else {
                stream
                    .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
            }
        }
    });

    let server_url = format!("http://{addr}");
    // `ag pdb apply` with no explicit PDB file fetches from `--server`, caches it,
    // and writes names, types, prototypes, and locals into the project.
    let apply_out = ag(&[
        "pdb",
        "apply",
        "--binary",
        exe_path.to_str().unwrap(),
        "--project",
        proj_path.to_str().unwrap(),
        "--server",
        &server_url,
        "--cache",
        cache_dir.to_str().unwrap(),
        "--json",
    ]);
    srv.join().unwrap();

    let summary: serde_json::Value = serde_json::from_str(&apply_out).unwrap();
    assert_eq!(summary["named"], 1);
    assert_eq!(summary["labeled"], 1);
    assert_eq!(summary["prototyped"], 1);
    assert_eq!(summary["locals_added"], 2);
    assert_eq!(summary["types_added"], 1);

    let proj = project_json(&proj_path);
    let anns = proj["annotations"].as_array().unwrap();
    let func = anns
        .iter()
        .find(|a| a["address"] == "0x140001000" && a["kind"] == "function")
        .expect("function annotation");
    assert_eq!(func["name"], "compute");
    assert_eq!(func["prototype"], "int32_t compute(int32_t a, int32_t b)");
    assert_eq!(func["stack_vars"][0]["offset"], -0x18);
    assert_eq!(func["stack_vars"][0]["name"], "sum");
    assert_eq!(func["var_types"][0]["variable"], "rbx");
    assert_eq!(func["var_types"][0]["type"], "int32_t");

    let reg_var = anns
        .iter()
        .find(|a| {
            a["address"] == "0x140001000"
                && a["kind"] == "variable"
                && a["variable"] == "rbx"
        })
        .expect("register variable annotation");
    assert_eq!(reg_var["name"], "tmp");

    // Verify lifted pseudocode uses the PDB function name, prototype, and stack local.
    let pseudo = ag(&[
        "image",
        exe_path.to_str().unwrap(),
        "pseudocode",
        "0x140001000",
        "--project",
        proj_path.to_str().unwrap(),
    ]);
    assert!(
        pseudo.contains("int32_t ") && pseudo.contains("(int32_t a, int32_t b)"),
        "{pseudo}"
    );
    assert!(pseudo.contains("int32_t sum;"), "{pseudo}");
    assert!(pseudo.contains("return sum;"), "{pseudo}");

    // `ag pdb fetch` now hits the local cache with no network request.
    let fetched_out = dir.join("out.pdb");
    let fetch_json: serde_json::Value = serde_json::from_str(&ag(&[
        "pdb",
        "fetch",
        exe_path.to_str().unwrap(),
        "--cache",
        cache_dir.to_str().unwrap(),
        "-o",
        fetched_out.to_str().unwrap(),
        "--json",
    ]))
    .unwrap();
    assert_eq!(fetch_json["cached"], true);
    assert!(fetched_out.is_file());

    // Analyst edits survive a second `apply`.
    let mut edited = proj;
    for a in edited["annotations"].as_array_mut().unwrap() {
        if a["address"] == "0x140001000" && a["kind"] == "function" {
            a["name"] = serde_json::json!("analyst_compute");
        }
    }
    std::fs::write(&proj_path, serde_json::to_string_pretty(&edited).unwrap()).unwrap();

    let second: serde_json::Value = serde_json::from_str(&ag(&[
        "pdb",
        "apply",
        fetched_out.to_str().unwrap(),
        "--binary",
        exe_path.to_str().unwrap(),
        "--project",
        proj_path.to_str().unwrap(),
        "--json",
    ]))
    .unwrap();
    assert_eq!(second["named"], 0);
    assert_eq!(second["prototyped"], 0);
    assert_eq!(second["locals_added"], 0);
    let after = project_json(&proj_path);
    let func_after = after["annotations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["address"] == "0x140001000" && a["kind"] == "function")
        .unwrap();
    assert_eq!(func_after["name"], "analyst_compute");

    // `--no-types --no-locals` leaves types and locals out.
    let min_proj = dir.join("min.agproj");
    let min_sum: serde_json::Value = serde_json::from_str(&ag(&[
        "pdb",
        "apply",
        fetched_out.to_str().unwrap(),
        "--binary",
        exe_path.to_str().unwrap(),
        "--project",
        min_proj.to_str().unwrap(),
        "--no-types",
        "--no-locals",
        "--json",
    ]))
    .unwrap();
    assert_eq!(min_sum["named"], 1);
    assert_eq!(min_sum["types_added"], 0);
    assert_eq!(min_sum["locals_added"], 0);

    let _ = std::fs::remove_dir_all(&dir);
}
