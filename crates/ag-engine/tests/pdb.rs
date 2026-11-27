//! Integration tests for `ag_engine::pdb`: PDB reading (functions,
//! prototypes, locals, data symbols, C types, line programs), PE CodeView
//! `RSDS` extraction, and symbol-server download + local cache (#400).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ag_engine::pdb::symsrv::{
    codeview_of_bytes, fetch_pdb, find_local_pdb, format_rsds_guid,
};
use ag_engine::pdb::{read_pdb, LocalLocation};
use ag_engine::types::DataModel;

struct PdbBuilder {
    guid: [u8; 16],
    age: u32,
    machine: u16,
    types: Vec<Vec<u8>>,
    globals: Vec<Vec<u8>>,
    mod_syms: Vec<Vec<u8>>,
    mod_lines: Vec<u8>,
    names: Vec<u8>,
}

impl PdbBuilder {
    fn new(guid: [u8; 16], age: u32, machine: u16) -> Self {
        let mut names = Vec::new();
        names.push(0); // offset 0 is empty string
        Self {
            guid,
            age,
            machine,
            types: Vec::new(),
            globals: Vec::new(),
            mod_syms: Vec::new(),
            mod_lines: Vec::new(),
            names,
        }
    }

    fn add_name(&mut self, s: &str) -> u32 {
        let off = self.names.len() as u32;
        self.names.extend_from_slice(s.as_bytes());
        self.names.push(0);
        off
    }

    fn add_type(&mut self, rec: Vec<u8>) -> u32 {
        let idx = 0x1000 + self.types.len() as u32;
        self.types.push(rec);
        idx
    }

    fn add_global_sym(&mut self, rec: Vec<u8>) {
        self.globals.push(rec);
    }

    fn add_mod_sym(&mut self, rec: Vec<u8>) {
        self.mod_syms.push(rec);
    }

    fn set_c13_lines(&mut self, file_name: &str, section: u16, offset: u32, line: u32) {
        let name_off = self.add_name(file_name);
        let mut out = Vec::new();
        // Subsection: FileChecksums (0xf4), 8 bytes per entry: name_off(4), len(1)=0, kind(1)=0, pad(2)=0.
        out.extend_from_slice(&0xf4u32.to_le_bytes());
        out.extend_from_slice(&8u32.to_le_bytes());
        out.extend_from_slice(&name_off.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);

        // Subsection: Lines (0xf2)
        // Header: offCon(4), segCon(2), flags(2), cbCon(4) = 12 bytes
        // FileBlock: offFile(4)=0, nLines(4)=1, cbBlock(4)=20 (12 header + 8 entry)
        // LineEntry: offset(4)=0, flags(4)=line | 0x80000000 (statement)
        let mut lines = Vec::new();
        lines.extend_from_slice(&offset.to_le_bytes());
        lines.extend_from_slice(&section.to_le_bytes());
        lines.extend_from_slice(&0u16.to_le_bytes());
        lines.extend_from_slice(&16u32.to_le_bytes());
        lines.extend_from_slice(&0u32.to_le_bytes()); // file_index = 0
        lines.extend_from_slice(&1u32.to_le_bytes()); // 1 line
        lines.extend_from_slice(&20u32.to_le_bytes()); // block len
        lines.extend_from_slice(&0u32.to_le_bytes()); // offset delta = 0
        lines.extend_from_slice(&(line | 0x8000_0000).to_le_bytes());

        out.extend_from_slice(&0xf2u32.to_le_bytes());
        out.extend_from_slice(&(lines.len() as u32).to_le_bytes());
        out.extend_from_slice(&lines);
        self.mod_lines = out;
    }

    fn build(&self) -> Vec<u8> {
        // Stream 1: PDBI
        let mut pdbi = Vec::new();
        pdbi.extend_from_slice(&20000404u32.to_le_bytes()); // VC70
        pdbi.extend_from_slice(&0x11223344u32.to_le_bytes()); // signature
        pdbi.extend_from_slice(&self.age.to_le_bytes());
        pdbi.extend_from_slice(&self.guid); // 16 bytes
        let stream_names = b"/names\0";
        pdbi.extend_from_slice(&(stream_names.len() as u32).to_le_bytes());
        pdbi.extend_from_slice(stream_names);
        // Hash table: size=1, capacity=1, present=[1, 1], deleted=[0], entry(0 -> stream 5)
        pdbi.extend_from_slice(&1u32.to_le_bytes());
        pdbi.extend_from_slice(&1u32.to_le_bytes());
        pdbi.extend_from_slice(&1u32.to_le_bytes()); // present words
        pdbi.extend_from_slice(&1u32.to_le_bytes()); // bit 0 set
        pdbi.extend_from_slice(&0u32.to_le_bytes()); // deleted words
        pdbi.extend_from_slice(&0u32.to_le_bytes()); // offset 0 ("/names")
        pdbi.extend_from_slice(&5u32.to_le_bytes()); // stream 5

        // Stream 2: TPI
        let mut tpi_recs = Vec::new();
        for r in &self.types {
            tpi_recs.extend_from_slice(&(r.len() as u16).to_le_bytes());
            tpi_recs.extend_from_slice(r);
        }
        let mut tpi = Vec::new();
        tpi.extend_from_slice(&20040203u32.to_le_bytes()); // V80
        tpi.extend_from_slice(&56u32.to_le_bytes()); // header_size
        tpi.extend_from_slice(&0x1000u32.to_le_bytes());
        tpi.extend_from_slice(&(0x1000 + self.types.len() as u32).to_le_bytes());
        tpi.extend_from_slice(&(tpi_recs.len() as u32).to_le_bytes());
        tpi.extend_from_slice(&0xffffu16.to_le_bytes()); // hash stream
        tpi.extend_from_slice(&0xffffu16.to_le_bytes()); // pad stream
        tpi.extend_from_slice(&0u32.to_le_bytes());
        tpi.extend_from_slice(&0u32.to_le_bytes());
        tpi.resize(56, 0);
        tpi.extend_from_slice(&tpi_recs);

        // Stream 4: empty IPI
        let ipi = Vec::new();

        // Stream 5: /names string table
        let mut strtab = Vec::new();
        strtab.extend_from_slice(&0xeffeeffeu32.to_le_bytes());
        strtab.extend_from_slice(&1u32.to_le_bytes()); // LongHash
        strtab.extend_from_slice(&(self.names.len() as u32).to_le_bytes());
        strtab.extend_from_slice(&self.names);
        strtab.extend_from_slice(&1u32.to_le_bytes()); // hash bucket count
        strtab.extend_from_slice(&1u32.to_le_bytes()); // hash entry
        strtab.extend_from_slice(&1u32.to_le_bytes()); // name count

        // Stream 6: Global symbol records
        let mut globals_stream = Vec::new();
        for s in &self.globals {
            globals_stream.extend_from_slice(&(s.len() as u16).to_le_bytes());
            globals_stream.extend_from_slice(s);
        }

        // Stream 7: Section headers (`.text` @ RVA 0x1000, `.data` @ RVA 0x3000)
        let mut sec_hdrs = Vec::new();
        sec_hdrs.extend_from_slice(&pe_section_hdr(b".text\0\0\0", 0x1000, 0x1000, 0x6000_0020));
        sec_hdrs.extend_from_slice(&pe_section_hdr(b".data\0\0\0", 0x1000, 0x3000, 0xc000_0040));

        // Stream 8: Module 0 stream
        let mut mod_stream = Vec::new();
        let mut mod_syms_bytes = Vec::new();
        mod_syms_bytes.extend_from_slice(&4u32.to_le_bytes()); // CV_SIGNATURE_C13
        for s in &self.mod_syms {
            mod_syms_bytes.extend_from_slice(&(s.len() as u16).to_le_bytes());
            mod_syms_bytes.extend_from_slice(s);
        }
        mod_stream.extend_from_slice(&mod_syms_bytes);
        mod_stream.extend_from_slice(&self.mod_lines);

        // Stream 3: DBI
        let mut mod_info = Vec::new();
        mod_info.extend_from_slice(&0u32.to_le_bytes()); // opened
        // DBISectionContribution (28 bytes): section(2), pad(2), offset(4), size(4), chars(4), mod(2), pad(2), crc(4), rcrc(4)
        mod_info.extend_from_slice(&1u16.to_le_bytes());
        mod_info.extend_from_slice(&0u16.to_le_bytes());
        mod_info.extend_from_slice(&0u32.to_le_bytes());
        mod_info.extend_from_slice(&0x100u32.to_le_bytes());
        mod_info.extend_from_slice(&0x6000_0020u32.to_le_bytes());
        mod_info.extend_from_slice(&0u16.to_le_bytes());
        mod_info.extend_from_slice(&0u16.to_le_bytes());
        mod_info.extend_from_slice(&0u32.to_le_bytes());
        mod_info.extend_from_slice(&0u32.to_le_bytes());
        mod_info.extend_from_slice(&0u16.to_le_bytes()); // flags
        mod_info.extend_from_slice(&8u16.to_le_bytes()); // module stream = 8
        mod_info.extend_from_slice(&(mod_syms_bytes.len() as u32).to_le_bytes());
        mod_info.extend_from_slice(&0u32.to_le_bytes()); // c11 lines
        mod_info.extend_from_slice(&(self.mod_lines.len() as u32).to_le_bytes());
        mod_info.extend_from_slice(&1u16.to_le_bytes()); // files
        mod_info.extend_from_slice(&0u16.to_le_bytes()); // pad
        mod_info.extend_from_slice(&0u32.to_le_bytes());
        mod_info.extend_from_slice(&0u32.to_le_bytes());
        mod_info.extend_from_slice(&0u32.to_le_bytes());
        mod_info.extend_from_slice(b"test.obj\0test.obj\0");
        while mod_info.len() % 4 != 0 {
            mod_info.push(0);
        }

        // DBIExtraStreams (6 u16s -> section_headers at index 5 = stream 7)
        let mut dbg_hdr = Vec::new();
        for i in 0..11u16 {
            let val = if i == 5 { 7u16 } else { 0xffffu16 };
            dbg_hdr.extend_from_slice(&val.to_le_bytes());
        }

        let mut dbi = Vec::new();
        dbi.extend_from_slice(&u32::MAX.to_le_bytes()); // signature
        dbi.extend_from_slice(&1999_09_03u32.to_le_bytes()); // V70
        dbi.extend_from_slice(&self.age.to_le_bytes());
        dbi.extend_from_slice(&0xffffu16.to_le_bytes()); // gs_symbols_stream
        dbi.extend_from_slice(&0u16.to_le_bytes());
        dbi.extend_from_slice(&0xffffu16.to_le_bytes()); // ps_symbols_stream
        dbi.extend_from_slice(&0u16.to_le_bytes());
        dbi.extend_from_slice(&6u16.to_le_bytes()); // symbol_records_stream = 6
        dbi.extend_from_slice(&0u16.to_le_bytes());
        dbi.extend_from_slice(&(mod_info.len() as u32).to_le_bytes());
        dbi.extend_from_slice(&0u32.to_le_bytes()); // section_contribution_size
        dbi.extend_from_slice(&0u32.to_le_bytes()); // section_map_size
        dbi.extend_from_slice(&0u32.to_le_bytes()); // file_info_size
        dbi.extend_from_slice(&0u32.to_le_bytes()); // type_server_map_size
        dbi.extend_from_slice(&0u32.to_le_bytes()); // mfc_type_server_index
        dbi.extend_from_slice(&(dbg_hdr.len() as u32).to_le_bytes());
        dbi.extend_from_slice(&0u32.to_le_bytes()); // ec_substream_size
        dbi.extend_from_slice(&0u16.to_le_bytes()); // flags
        dbi.extend_from_slice(&self.machine.to_le_bytes());
        dbi.extend_from_slice(&0u32.to_le_bytes()); // reserved
        dbi.extend_from_slice(&mod_info);
        dbi.extend_from_slice(&dbg_hdr);

        let streams = vec![
            Vec::new(), // 0
            pdbi,       // 1
            tpi,        // 2
            dbi,        // 3
            ipi,        // 4
            strtab,     // 5
            globals_stream, // 6
            sec_hdrs,   // 7
            mod_stream, // 8
        ];
        pack_msf(&streams, 4096)
    }
}

fn pe_section_hdr(name: &[u8; 8], vsize: u32, rva: u32, chars: u32) -> [u8; 40] {
    let mut h = [0u8; 40];
    h[0..8].copy_from_slice(name);
    h[8..12].copy_from_slice(&vsize.to_le_bytes());
    h[12..16].copy_from_slice(&rva.to_le_bytes());
    h[16..20].copy_from_slice(&vsize.to_le_bytes());
    h[36..40].copy_from_slice(&chars.to_le_bytes());
    h
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
    let magic = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";
    file[..32].copy_from_slice(magic);
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

fn pad4(v: &mut Vec<u8>) {
    let rem = v.len() % 4;
    if rem != 0 {
        for i in (1..=(4 - rem)).rev() {
            v.push(0xf0 + i as u8);
        }
    }
}

fn rec_fieldlist(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut r = 0x1203u16.to_le_bytes().to_vec();
    for item in items {
        r.extend_from_slice(&item);
        pad4(&mut r);
    }
    r
}

fn rec_member(ty: u32, offset: u16, name: &str) -> Vec<u8> {
    let mut r = 0x150du16.to_le_bytes().to_vec();
    r.extend_from_slice(&3u16.to_le_bytes()); // public
    r.extend_from_slice(&ty.to_le_bytes());
    r.extend_from_slice(&offset.to_le_bytes());
    r.extend_from_slice(name.as_bytes());
    r.push(0);
    r
}

fn rec_enumerate(val: u16, name: &str) -> Vec<u8> {
    let mut r = 0x1502u16.to_le_bytes().to_vec();
    r.extend_from_slice(&3u16.to_le_bytes());
    r.extend_from_slice(&val.to_le_bytes());
    r.extend_from_slice(name.as_bytes());
    r.push(0);
    r
}

fn rec_struct(count: u16, props: u16, fields: u32, derived: u32, size: u16, name: &str) -> Vec<u8> {
    let mut r = 0x1505u16.to_le_bytes().to_vec();
    r.extend_from_slice(&count.to_le_bytes());
    r.extend_from_slice(&props.to_le_bytes());
    r.extend_from_slice(&fields.to_le_bytes());
    r.extend_from_slice(&derived.to_le_bytes());
    r.extend_from_slice(&0u32.to_le_bytes()); // vshape
    r.extend_from_slice(&size.to_le_bytes());
    r.extend_from_slice(name.as_bytes());
    r.push(0);
    r
}

fn rec_enum(count: u16, underlying: u32, fields: u32, name: &str) -> Vec<u8> {
    let mut r = 0x1507u16.to_le_bytes().to_vec();
    r.extend_from_slice(&count.to_le_bytes());
    r.extend_from_slice(&0u16.to_le_bytes());
    r.extend_from_slice(&underlying.to_le_bytes());
    r.extend_from_slice(&fields.to_le_bytes());
    r.extend_from_slice(name.as_bytes());
    r.push(0);
    r
}

fn rec_union(count: u16, fields: u32, size: u16, name: &str) -> Vec<u8> {
    let mut r = 0x1506u16.to_le_bytes().to_vec();
    r.extend_from_slice(&count.to_le_bytes());
    r.extend_from_slice(&0u16.to_le_bytes());
    r.extend_from_slice(&fields.to_le_bytes());
    r.extend_from_slice(&size.to_le_bytes());
    r.extend_from_slice(name.as_bytes());
    r.push(0);
    r
}

fn rec_arglist(args: &[u32]) -> Vec<u8> {
    let mut r = 0x1201u16.to_le_bytes().to_vec();
    r.extend_from_slice(&(args.len() as u32).to_le_bytes());
    for a in args {
        r.extend_from_slice(&a.to_le_bytes());
    }
    r
}

fn rec_procedure(ret: u32, cc: u8, arg_count: u16, arglist: u32) -> Vec<u8> {
    let mut r = 0x1008u16.to_le_bytes().to_vec();
    r.extend_from_slice(&ret.to_le_bytes());
    r.push(cc);
    r.push(0);
    r.extend_from_slice(&arg_count.to_le_bytes());
    r.extend_from_slice(&arglist.to_le_bytes());
    r
}

fn rec_array(elem: u32, idx: u32, total_bytes: u16) -> Vec<u8> {
    let mut r = 0x1503u16.to_le_bytes().to_vec();
    r.extend_from_slice(&elem.to_le_bytes());
    r.extend_from_slice(&idx.to_le_bytes());
    r.extend_from_slice(&total_bytes.to_le_bytes());
    r.push(0); // end of dimensions
    r
}

fn rec_bitfield(underlying: u32, len: u8, pos: u8) -> Vec<u8> {
    let mut r = 0x1205u16.to_le_bytes().to_vec();
    r.extend_from_slice(&underlying.to_le_bytes());
    r.push(len);
    r.push(pos);
    r
}

fn rec_bclass(base: u32, offset: u16) -> Vec<u8> {
    let mut r = 0x1400u16.to_le_bytes().to_vec();
    r.extend_from_slice(&3u16.to_le_bytes());
    r.extend_from_slice(&base.to_le_bytes());
    r.extend_from_slice(&offset.to_le_bytes());
    r
}

fn sym_gproc32(len: u32, ty: u32, offset: u32, section: u16, name: &str) -> Vec<u8> {
    let mut s = 0x1110u16.to_le_bytes().to_vec(); // S_GPROC32
    s.extend_from_slice(&0u32.to_le_bytes()); // parent
    s.extend_from_slice(&0u32.to_le_bytes()); // end
    s.extend_from_slice(&0u32.to_le_bytes()); // next
    s.extend_from_slice(&len.to_le_bytes());
    s.extend_from_slice(&0u32.to_le_bytes()); // dbgStart
    s.extend_from_slice(&len.to_le_bytes()); // dbgEnd
    s.extend_from_slice(&ty.to_le_bytes());
    s.extend_from_slice(&offset.to_le_bytes());
    s.extend_from_slice(&section.to_le_bytes());
    s.push(0); // flags
    s.extend_from_slice(name.as_bytes());
    s.push(0);
    s
}

fn sym_local(ty: u32, is_param: bool, name: &str) -> Vec<u8> {
    let mut s = 0x113eu16.to_le_bytes().to_vec(); // S_LOCAL
    s.extend_from_slice(&ty.to_le_bytes());
    s.extend_from_slice(&(if is_param { 1u16 } else { 0u16 }).to_le_bytes());
    s.extend_from_slice(name.as_bytes());
    s.push(0);
    s
}

fn sym_regrel32(offset: i32, ty: u32, reg: u16, name: &str) -> Vec<u8> {
    let mut s = 0x1111u16.to_le_bytes().to_vec(); // S_REGREL32
    s.extend_from_slice(&offset.to_le_bytes());
    s.extend_from_slice(&ty.to_le_bytes());
    s.extend_from_slice(&reg.to_le_bytes());
    s.extend_from_slice(name.as_bytes());
    s.push(0);
    s
}

fn sym_register(ty: u32, reg: u16, name: &str) -> Vec<u8> {
    let mut s = 0x1106u16.to_le_bytes().to_vec(); // S_REGISTER
    s.extend_from_slice(&ty.to_le_bytes());
    s.extend_from_slice(&reg.to_le_bytes());
    s.extend_from_slice(name.as_bytes());
    s.push(0);
    s
}

fn sym_defrange_fp_rel(offset: i32) -> Vec<u8> {
    let mut s = 0x1142u16.to_le_bytes().to_vec(); // S_DEFRANGE_FRAMEPOINTER_REL
    s.extend_from_slice(&offset.to_le_bytes());
    s.extend_from_slice(&[0u8; 8]); // range
    s
}

fn sym_end() -> Vec<u8> {
    0x0006u16.to_le_bytes().to_vec()
}

fn sym_gdata32(ty: u32, offset: u32, section: u16, name: &str) -> Vec<u8> {
    let mut s = 0x110du16.to_le_bytes().to_vec(); // S_GDATA32
    s.extend_from_slice(&ty.to_le_bytes());
    s.extend_from_slice(&offset.to_le_bytes());
    s.extend_from_slice(&section.to_le_bytes());
    s.extend_from_slice(name.as_bytes());
    s.push(0);
    s
}

fn sym_pub32(flags: u32, offset: u32, section: u16, name: &str) -> Vec<u8> {
    let mut s = 0x110eu16.to_le_bytes().to_vec(); // S_PUB32
    s.extend_from_slice(&flags.to_le_bytes());
    s.extend_from_slice(&offset.to_le_bytes());
    s.extend_from_slice(&section.to_le_bytes());
    s.extend_from_slice(name.as_bytes());
    s.push(0);
    s
}

fn sym_udt(ty: u32, name: &str) -> Vec<u8> {
    let mut s = 0x1108u16.to_le_bytes().to_vec(); // S_UDT
    s.extend_from_slice(&ty.to_le_bytes());
    s.extend_from_slice(name.as_bytes());
    s.push(0);
    s
}

/// Build a minimal valid PE32+ image containing an RSDS CodeView debug entry.
fn minimal_pe64_with_rsds(guid: [u8; 16], age: u32, pdb_path: &str) -> Vec<u8> {
    let mut pe = vec![0u8; 0x600];
    pe[0] = b'M';
    pe[1] = b'Z';
    let pe_off = 0x80usize;
    pe[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    // COFF header: Machine=0x8664, NumberOfSections=1, SizeOfOptionalHeader=240, Characteristics=0x22
    let coff = pe_off + 4;
    pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
    pe[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

    let opt = coff + 20;
    pe[opt..opt + 2].copy_from_slice(&0x020bu16.to_le_bytes()); // PE32+
    pe[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EntryPoint RVA
    pe[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase
    pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    pe[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    pe[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
    pe[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // DataDirectory[6] (Debug) at opt + 112 + 6 * 8 = opt + 160
    let debug_dir_rva = 0x1020u32;
    let debug_dir_raw = 0x220usize;
    pe[opt + 160..opt + 164].copy_from_slice(&debug_dir_rva.to_le_bytes());
    pe[opt + 164..opt + 168].copy_from_slice(&28u32.to_le_bytes());

    // Section header 0: `.text` RVA=0x1000, VSize=0x400, RawOff=0x200, RawSize=0x400
    let sec = opt + 240;
    pe[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    pe[sec + 8..sec + 12].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[sec + 16..sec + 20].copy_from_slice(&0x400u32.to_le_bytes());
    pe[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
    pe[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // Minimal function bytes at RVA 0x1000 (file 0x200): `ret`
    pe[0x200] = 0xc3;

    // CodeView RSDS payload at file 0x260 (RVA 0x1060)
    let rsds_raw = 0x260usize;
    let rsds_rva = 0x1060u32;
    let mut rsds = b"RSDS".to_vec();
    rsds.extend_from_slice(&guid);
    rsds.extend_from_slice(&age.to_le_bytes());
    rsds.extend_from_slice(pdb_path.as_bytes());
    rsds.push(0);
    pe[rsds_raw..rsds_raw + rsds.len()].copy_from_slice(&rsds);

    // IMAGE_DEBUG_DIRECTORY (28 bytes) at debug_dir_raw
    pe[debug_dir_raw + 12..debug_dir_raw + 16].copy_from_slice(&2u32.to_le_bytes()); // IMAGE_DEBUG_TYPE_CODEVIEW
    pe[debug_dir_raw + 16..debug_dir_raw + 20]
        .copy_from_slice(&(rsds.len() as u32).to_le_bytes());
    pe[debug_dir_raw + 20..debug_dir_raw + 24].copy_from_slice(&rsds_rva.to_le_bytes());
    pe[debug_dir_raw + 24..debug_dir_raw + 28].copy_from_slice(&(rsds_raw as u32).to_le_bytes());

    pe
}

fn sample_pdb_bytes(guid: [u8; 16], age: u32) -> Vec<u8> {
    let mut b = PdbBuilder::new(guid, age, 0x8664);

    // Forward reference to `Point` before its real definition.
    b.add_type(rec_struct(0, 0x0080, 0, 0, 0, "Point"));
    let pt_fields = b.add_type(rec_fieldlist(vec![
        rec_member(0x0074, 0, "x"), // int32_t
        rec_member(0x0074, 4, "y"),
    ]));
    let pt_struct = b.add_type(rec_struct(2, 0, pt_fields, 0, 8, "Point"));

    // Enum
    let enum_fields = b.add_type(rec_fieldlist(vec![
        rec_enumerate(1, "RED"),
        rec_enumerate(2, "GREEN"),
    ]));
    let _color_enum = b.add_type(rec_enum(2, 0x0074, enum_fields, "Color"));

    // Union
    let union_fields = b.add_type(rec_fieldlist(vec![
        rec_member(0x0074, 0, "i"),
        rec_member(0x0076, 0, "l"),
    ]));
    let _val_union = b.add_type(rec_union(2, union_fields, 8, "Value"));

    // Bitfield struct
    let bf_ty = b.add_type(rec_bitfield(0x0075, 1, 0)); // uint32_t : 1
    let bf_fields = b.add_type(rec_fieldlist(vec![rec_member(bf_ty, 0, "active")]));
    let _flags_struct = b.add_type(rec_struct(1, 0, bf_fields, 0, 4, "Flags"));

    // C++ class with base class -> must be held back
    let derived_fields = b.add_type(rec_fieldlist(vec![
        rec_bclass(pt_struct, 0),
        rec_member(0x0074, 8, "z"),
    ]));
    let _derived = b.add_type(rec_struct(2, 0, derived_fields, pt_struct, 12, "Derived"));

    // Array int[4] (16 bytes)
    let arr_ty = b.add_type(rec_array(0x0074, 0x0075, 16));

    // Procedure: int sum_points(int count, int dummy)
    let arglist = b.add_type(rec_arglist(&[0x0074, 0x0074]));
    let proc_ty = b.add_type(rec_procedure(0x0074, 0, 2, arglist));

    // Typedef: typedef struct Point PointAlias;
    b.add_global_sym(sym_udt(pt_struct, "PointAlias"));
    b.add_global_sym(sym_gdata32(arr_ty, 0x0, 2, "g_table"));
    b.add_global_sym(sym_pub32(0x3, 0x40, 1, "?helper@ns@@YAHH@Z")); // RVA 0x1040

    // Procedure with params + stack/register locals + line number
    b.add_mod_sym(sym_gproc32(0x30, proc_ty, 0, 1, "sum_points")); // RVA 0x1000
    b.add_mod_sym(sym_local(0x0074, true, "count"));
    b.add_mod_sym(sym_local(0x0074, true, "extra"));
    b.add_mod_sym(sym_regrel32(-0x10, 0x0074, 334 /* rbp */, "total"));
    b.add_mod_sym(sym_local(0x0074, false, "cached"));
    b.add_mod_sym(sym_defrange_fp_rel(-0x18));
    b.add_mod_sym(sym_register(0x0074, 329 /* rbx */, "acc"));
    b.add_mod_sym(sym_end());

    b.set_c13_lines(r"C:\src\math.c", 1, 0, 42);
    b.build()
}

#[test]
fn reads_functions_prototypes_locals_data_types_and_sources() {
    let guid = [
        0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ];
    let bytes = sample_pdb_bytes(guid, 2);
    let info = read_pdb(&bytes, Some(DataModel::LLP64)).expect("PDB parses");

    assert_eq!(info.guid, "123456789ABCDEF01122334455667788");
    assert_eq!(info.age, 2);
    assert_eq!(info.id, "123456789ABCDEF011223344556677882");
    assert_eq!(info.machine, "x64");
    assert_eq!(info.types_held_back, 1); // Derived (base class)

    assert!(info.types.iter().any(|t| t.contains("struct Point")));
    assert!(info.types.iter().any(|t| t.contains("enum Color")));
    assert!(info.types.iter().any(|t| t.contains("union Value")));
    assert!(info
        .types
        .iter()
        .any(|t| t.contains("active : 1")));
    assert!(info
        .types
        .iter()
        .any(|t| t.contains("typedef struct Point PointAlias;")));

    assert_eq!(info.functions.len(), 2);
    let f = &info.functions[0];
    assert_eq!(f.rva, 0x1000);
    assert_eq!(f.size, Some(0x30));
    assert_eq!(f.name, "sum_points");
    assert_eq!(
        f.prototype.as_deref(),
        Some("int32_t sum_points(int32_t count, int32_t extra)")
    );
    assert_eq!(f.source.as_deref(), Some("math.c:42"));
    assert_eq!(f.locals.len(), 3);
    assert_eq!(
        f.locals[0].location,
        LocalLocation::Stack {
            offset: -0x18, // -0x10 - 8
            size: 4,
        }
    );
    assert_eq!(f.locals[0].name, "total");
    assert_eq!(
        f.locals[1].location,
        LocalLocation::Stack {
            offset: -0x20, // -0x18 - 8
            size: 4,
        }
    );
    assert_eq!(f.locals[1].name, "cached");
    assert_eq!(
        f.locals[2].location,
        LocalLocation::Register {
            register: "rbx".to_string(),
            size: Some(4),
        }
    );
    assert_eq!(f.locals[2].name, "acc");

    let pub_fn = &info.functions[1];
    assert_eq!(pub_fn.rva, 0x1040);
    assert_eq!(pub_fn.name, "ns::helper(int)");

    assert_eq!(info.data.len(), 1);
    assert_eq!(info.data[0].rva, 0x3000);
    assert_eq!(info.data[0].name, "g_table");
    assert_eq!(info.data[0].size, Some(16));
    assert_eq!(info.data[0].ctype.as_deref(), Some("int32_t[4]"));
}

#[test]
fn extracts_codeview_and_fetches_via_redirect_and_cache() {
    let guid = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ];
    let pe = minimal_pe64_with_rsds(guid, 3, r"C:\out\sample_app.pdb");
    let cv = codeview_of_bytes(&pe)
        .expect("PE parses")
        .expect("RSDS present");
    assert_eq!(cv.guid_hex, format_rsds_guid(&guid));
    assert_eq!(cv.guid_hex, "443322116655887799AABBCCDDEEFF00");
    assert_eq!(cv.age, 3);
    assert_eq!(cv.filename, "sample_app.pdb");
    assert_eq!(cv.id, "443322116655887799AABBCCDDEEFF003");

    let pdb_bytes = Arc::new(sample_pdb_bytes(guid, 3));
    let expected_path = format!("/symbols/sample_app.pdb/{}/sample_app.pdb", cv.id);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);
    let pdb_srv = Arc::clone(&pdb_bytes);

    let handle = std::thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            let req_line = req.lines().next().unwrap_or("");
            hits_srv.fetch_add(1, Ordering::SeqCst);
            if req_line.starts_with(&format!("GET {expected_path} ")) {
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{addr}/cdn/sample_app.pdb\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(resp.as_bytes()).unwrap();
            } else if req_line.starts_with("GET /cdn/sample_app.pdb ") {
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

    let cache_dir: PathBuf = std::env::temp_dir().join(format!(
        "ag-pdb-cache-test-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&cache_dir);

    let server_url = format!("http://{addr}/symbols");
    let first = fetch_pdb(&cv, &[server_url.clone()], &cache_dir, None).expect("downloads PDB");
    assert!(!first.cached);
    assert_eq!(first.source, server_url);
    assert!(first.path.is_file());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    handle.join().unwrap();

    // Second lookup finds it in cache with no network request.
    assert!(find_local_pdb(None, &cv, Some(&cache_dir)).is_some());
    let second = fetch_pdb(&cv, &[], &cache_dir, None).expect("reads from cache");
    assert!(second.cached);
    assert_eq!(second.source, "cache");
    assert_eq!(second.path, first.path);

    let _ = std::fs::remove_dir_all(&cache_dir);
}
