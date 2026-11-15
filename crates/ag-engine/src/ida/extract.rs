//! Gather a database into the names, comments, functions, segments and
//! root facts a project applies or a report shows.
//!
//! The names are the `nam` section's addresses, each named by its netnode;
//! the functions are the `$ funcs` node's `func_t` supvals, with their
//! comments on the same node's `C` and `R` tags; the comments of an address
//! are its netnode's supvals — 0 the regular, 1 the repeatable, 1000+n the
//! anterior lines and 2000+n the posterior; the segments are the `$ segs`
//! node, their names in `$ segstrings`.

use super::container::{self, Database};
use super::netnode::{string_of, Netnodes};

/// Why a database did not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractError(pub String);

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ExtractError {}

impl From<container::ContainerError> for ExtractError {
    fn from(e: container::ContainerError) -> Self {
        ExtractError(e.0)
    }
}

/// A database read whole: the index, its netnodes, and the sections.
#[derive(Debug, Clone)]
pub struct Idb {
    /// The container: index and sections.
    pub db: Database,
    /// The netnodes read from the index.
    pub nodes: Netnodes,
}

/// The root facts of a database: what IDA version wrote it, the image it
/// describes, and the file it was made from.
#[derive(Debug, Clone, Default)]
pub struct RootInfo {
    /// The IDA version that wrote the database, e.g. 695 or 700.
    pub version: i64,
    /// The version as IDA spells it, e.g. "6.95".
    pub version_string: String,
    /// The address the image loads at; 0 when the database does not say.
    pub imagebase: u64,
    /// The MD5 of the input file, as lowercase hex, when recorded.
    pub md5: Option<String>,
    /// The path of the file the database was made from, when recorded.
    pub input_file_path: Option<String>,
    /// The processor module, e.g. "metapc".
    pub procname: String,
    /// The input file type IDA loaded (2 a binary, 18 an ELF, 11 a PE).
    pub filetype: u16,
    /// The loader flags.
    pub lflags: u32,
}

/// One function the database knows.
#[derive(Debug, Clone)]
pub struct Function {
    /// The entry address.
    pub start: u64,
    /// The address just past the function's last byte.
    pub end: u64,
    /// The function flags; bit 0x8000 marks a tail chunk, not an entry.
    pub flags: u32,
    /// The name, when the function's netnode has one.
    pub name: Option<String>,
    /// The regular function comment (`$ funcs`.C).
    pub comment: Option<String>,
    /// The repeatable function comment (`$ funcs`.R).
    pub repeatable_comment: Option<String>,
}

impl Function {
    /// Whether this record is a tail chunk rather than a function entry.
    pub fn is_tail(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

/// One segment of the image.
#[derive(Debug, Clone)]
pub struct Segment {
    /// The first address.
    pub start: u64,
    /// The address just past the segment.
    pub end: u64,
    /// The segment name, e.g. ".text".
    pub name: String,
    /// The segment class, e.g. "CODE", "DATA".
    pub class: String,
    /// 0 for 16-bit, 1 for 32-bit, 2 for 64-bit addressing.
    pub bitness: u32,
    /// The permissions: 1 execute, 2 write, 4 read.
    pub perm: u32,
}

/// A comment on one address: which kind, and its text. Anterior and
/// posterior comments come in lines, numbered from 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// The address the comment is on.
    pub address: u64,
    /// Which kind of comment it is.
    pub kind: CommentKind,
    /// The line number of an anterior or posterior comment; 0 otherwise.
    pub line: u32,
    /// The text.
    pub text: String,
}

/// The kinds of comment IDA keeps on an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentKind {
    /// The regular comment, shown at the end of the line.
    Regular,
    /// The repeatable comment, shown wherever the address is referenced.
    Repeatable,
    /// A line above the address.
    Anterior,
    /// A line below the address.
    Posterior,
}

impl Idb {
    /// Read a database from its bytes.
    pub fn parse(bytes: &[u8]) -> Result<Idb, ExtractError> {
        let db = container::parse(bytes)?;
        let nodes = Netnodes::read(&db);
        Ok(Idb { db, nodes })
    }

    /// The width of an address: 4 or 8.
    pub fn wordsize(&self) -> usize {
        self.db.wordsize
    }

    /// The root facts.
    pub fn root(&self) -> RootInfo {
        let mut info = RootInfo::default();
        let Some(root) = self.nodes.by_name("Root Node") else {
            return info;
        };
        info.version = root.altval(-1).unwrap_or(0);
        info.version_string = root.supstr(1303).unwrap_or_default();
        info.imagebase = root.altval(-6).unwrap_or(0) as u64;
        info.md5 = root
            .sup
            .get(&1302)
            .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
        info.input_file_path = root.value.as_deref().map(string_of);
        if let Some(blob) = root.sup.get(&0x41B994) {
            if let Some(inf) = IdaInfo::parse(blob) {
                info.procname = inf.procname;
                info.filetype = inf.filetype;
                info.lflags = inf.lflags;
            }
        }
        info
    }

    /// The named addresses, in address order: the `nam` section's pointers,
    /// each named by its netnode.
    pub fn names(&self) -> Vec<(u64, String)> {
        let mut out = Vec::new();
        for ea in nam_addresses(&self.db.nam, self.db.wordsize) {
            if let Some(name) = self.nodes.name_of(ea) {
                out.push((ea, name.to_string()));
            }
        }
        out.sort_by_key(|(ea, _)| *ea);
        out
    }

    /// The functions, in entry-address order, tail chunks included.
    pub fn functions(&self) -> Vec<Function> {
        let mut out = Vec::new();
        let Some(funcs) = self.nodes.by_name("$ funcs") else {
            return out;
        };
        // A function is recorded at an address within a segment; the
        // `$ funcs` node also carries supvals outside them, which the
        // index's segment bounds tell apart.
        let bounds = id1_bounds(&self.db.id1, self.db.wordsize);
        for (&index, value) in &funcs.sup {
            if index < 0 {
                continue;
            }
            let ea = index as u64;
            if !bounds.is_empty() && !bounds.iter().any(|(s, e)| ea >= *s && ea < *e) {
                continue;
            }
            let Some((start, end, flags)) = parse_func_t(value, self.db.wordsize) else {
                continue;
            };
            out.push(Function {
                start,
                end,
                flags,
                name: self.nodes.name_of(ea).map(str::to_string),
                comment: funcs.char.get(&index).map(|b| string_of(b)),
                repeatable_comment: funcs.r.get(&index).map(|b| string_of(b)),
            });
        }
        out.sort_by_key(|f| f.start);
        out
    }

    /// The segments, in start-address order.
    pub fn segments(&self) -> Vec<Segment> {
        let mut out = Vec::new();
        let Some(segs) = self.nodes.by_name("$ segs") else {
            return out;
        };
        let strings = seg_strings(self.nodes.by_name("$ segstrings"));
        for (&index, value) in &segs.sup {
            if index < 0 {
                continue;
            }
            let Some(seg) = parse_seg(value, self.db.wordsize, &strings) else {
                continue;
            };
            out.push(seg);
        }
        out.sort_by_key(|s| s.start);
        out
    }

    /// Every comment on every address, in address then kind then line order.
    pub fn comments(&self) -> Vec<Comment> {
        let mut out = Vec::new();
        for ea in self.nodes.addresses() {
            let Some(node) = self.nodes.node(ea) else {
                continue;
            };
            if let Some(text) = node.supstr(0) {
                if !text.is_empty() {
                    out.push(Comment {
                        address: ea,
                        kind: CommentKind::Regular,
                        line: 0,
                        text,
                    });
                }
            }
            if let Some(text) = node.supstr(1) {
                if !text.is_empty() {
                    out.push(Comment {
                        address: ea,
                        kind: CommentKind::Repeatable,
                        line: 0,
                        text,
                    });
                }
            }
            for (&index, value) in &node.sup {
                let text = string_of(value);
                if text.is_empty() {
                    continue;
                }
                if (1000..2000).contains(&index) {
                    out.push(Comment {
                        address: ea,
                        kind: CommentKind::Anterior,
                        line: (index - 1000) as u32,
                        text,
                    });
                } else if (2000..3000).contains(&index) {
                    out.push(Comment {
                        address: ea,
                        kind: CommentKind::Posterior,
                        line: (index - 2000) as u32,
                        text,
                    });
                }
            }
        }
        out.sort_by(|a, b| {
            a.address
                .cmp(&b.address)
                .then((a.kind as u8).cmp(&(b.kind as u8)))
                .then(a.line.cmp(&b.line))
        });
        out
    }

    /// The local type library's bytes, when the database carries one.
    pub fn til_bytes(&self) -> Option<&[u8]> {
        self.db.til.as_deref()
    }

    /// A function's packed prototype and its argument names: the netnode
    /// at the entry holds the type at supval 0x3000 and the names at
    /// 0x3001. `None` when the function has no prototype recorded.
    pub fn function_prototype_bytes(&self, ea: u64) -> Option<(Vec<u8>, Vec<String>)> {
        let node = self.nodes.node(ea)?;
        let type_info = node.sup.get(&0x3000)?.clone();
        let arg_names = node
            .sup
            .get(&0x3001)
            .map(|bytes| arg_names_of(bytes))
            .unwrap_or_default();
        Some((type_info, arg_names))
    }
}

/// The argument names of a prototype: length-prefixed strings, each a
/// length byte counting itself then the characters.
fn arg_names_of(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let length = buf[pos] as usize;
        pos += 1;
        if length == 0 {
            break;
        }
        let end = (pos + length - 1).min(buf.len());
        out.push(String::from_utf8_lossy(&buf[pos..end]).into_owned());
        pos += length - 1;
    }
    out
}

/// The addresses the `nam` section points at.
fn nam_addresses(nam: &[u8], wordsize: usize) -> Vec<u64> {
    // The header is 24 bytes plus the word, padded to a 0x2000 page; the
    // names are the first `dword_count` words of the buffer that follows.
    if nam.len() < 0x2000 || &nam[0..4] != b"VA*\0" {
        return Vec::new();
    }
    // The header is six dwords plus one word; dword_count follows unk14.
    let at = 20 + wordsize;
    let dword_count = u32::from_le_bytes([nam[at], nam[at + 1], nam[at + 2], nam[at + 3]]) as usize;
    let count = if wordsize == 8 {
        dword_count / 2
    } else {
        dword_count
    };
    let buffer = &nam[0x2000..];
    let mut out = Vec::new();
    for i in 0..count {
        let at = i * wordsize;
        if at + wordsize > buffer.len() {
            break;
        }
        let ea = if wordsize == 8 {
            u64::from_le_bytes([
                buffer[at],
                buffer[at + 1],
                buffer[at + 2],
                buffer[at + 3],
                buffer[at + 4],
                buffer[at + 5],
                buffer[at + 6],
                buffer[at + 7],
            ])
        } else {
            u64::from(u32::from_le_bytes([
                buffer[at],
                buffer[at + 1],
                buffer[at + 2],
                buffer[at + 3],
            ]))
        };
        out.push(ea);
    }
    out
}

/// The segment bounds the `id1` section opens with: each a start and an
/// end, and an offset in the older `Va4` layout.
fn id1_bounds(id1: &[u8], wordsize: usize) -> Vec<(u64, u64)> {
    if id1.len() < 8 {
        return Vec::new();
    }
    let sig = &id1[0..4];
    let (count, mut pos, has_ofs) = if sig == b"VA*\0" {
        (le32(id1, 8) as usize, 20usize, false)
    } else if sig == b"Va4\0" {
        (u16::from_le_bytes([id1[4], id1[5]]) as usize, 8usize, true)
    } else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for _ in 0..count {
        if pos + 2 * wordsize > id1.len() {
            break;
        }
        let start = le_word(id1, pos, wordsize);
        let end = le_word(id1, pos + wordsize, wordsize);
        pos += 2 * wordsize;
        if has_ofs {
            pos += wordsize;
        }
        out.push((start, end));
    }
    out
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn le_word(bytes: &[u8], at: usize, wordsize: usize) -> u64 {
    if wordsize == 8 {
        u64::from_le_bytes([
            bytes[at],
            bytes[at + 1],
            bytes[at + 2],
            bytes[at + 3],
            bytes[at + 4],
            bytes[at + 5],
            bytes[at + 6],
            bytes[at + 7],
        ])
    } else {
        u64::from(le32(bytes, at))
    }
}

/// A cursor over IDA's packed integers: a dword, word or qword, and an
/// address of the database's width.
struct Packed<'a> {
    buf: &'a [u8],
    pos: usize,
    wordsize: usize,
}

impl<'a> Packed<'a> {
    fn new(buf: &'a [u8], wordsize: usize) -> Packed<'a> {
        Packed {
            buf,
            pos: 0,
            wordsize,
        }
    }

    fn byte(&mut self) -> Option<u8> {
        let byte = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    /// Up to 32 bits, in IDA's packing: a leading byte says how many follow.
    fn dd(&mut self) -> Option<u32> {
        let header = self.byte()?;
        if header & 0x80 == 0 {
            Some(u32::from(header))
        } else if header & 0xC0 != 0xC0 {
            let next = self.byte()?;
            Some((u32::from(header & 0x7F) << 8) + u32::from(next))
        } else if header & 0xE0 == 0xE0 {
            let b1 = self.byte()?;
            let b2 = self.byte()?;
            let b3 = self.byte()?;
            let b4 = self.byte()?;
            let hi = (u32::from(b1) << 8) + u32::from(b2);
            let low = (u32::from(b3) << 8) + u32::from(b4);
            Some((hi << 16) + low)
        } else {
            let b1 = self.byte()?;
            let b2 = self.byte()?;
            let b3 = self.byte()?;
            let hi = (u32::from(header & 0x3F) << 8) + u32::from(b1);
            let low = (u32::from(b2) << 8) + u32::from(b3);
            Some((hi << 16) + low)
        }
    }

    /// Up to 16 bits.
    fn dw(&mut self) -> Option<u16> {
        let header = self.byte()?;
        if header & 0x80 == 0 {
            Some(u16::from(header))
        } else if header & 0xC0 != 0xC0 {
            let next = self.byte()?;
            Some(((u16::from(header) << 8) + u16::from(next)) & 0x7FFF)
        } else {
            let b1 = self.byte()?;
            let b2 = self.byte()?;
            Some((u16::from(b1) << 8) + u16::from(b2))
        }
    }

    /// Up to 64 bits: two dwords, low first.
    fn dq(&mut self) -> Option<u64> {
        let low = self.dd()?;
        let high = self.dd()?;
        Some((u64::from(high) << 32) + u64::from(low))
    }

    /// An address of the database's width.
    fn addr(&mut self) -> Option<u64> {
        if self.wordsize == 4 {
            self.dd().map(u64::from)
        } else {
            self.dq()
        }
    }
}

/// Read a `func_t`: the entry, the size, the flags.
fn parse_func_t(bytes: &[u8], wordsize: usize) -> Option<(u64, u64, u32)> {
    let mut p = Packed::new(bytes, wordsize);
    let start = p.addr()?;
    let size = p.addr()?;
    let flags = p.dw()?;
    Some((start, start.wrapping_add(size), u32::from(flags)))
}

/// Read one segment of the `$ segs` node.
fn parse_seg(bytes: &[u8], wordsize: usize, strings: &[String]) -> Option<Segment> {
    let mut p = Packed::new(bytes, wordsize);
    let start = p.addr()?;
    let size = p.addr()?;
    let name_index = p.addr()? as usize;
    let class_index = p.addr()? as usize;
    let _orgbase = p.addr()?;
    let _flags = p.dd()?;
    let _align = p.dd()?;
    let _comb = p.dd()?;
    let perm = p.dd()?;
    let bitness = p.dd()?;
    Some(Segment {
        start,
        end: start.wrapping_add(size),
        name: strings.get(name_index).cloned().unwrap_or_default(),
        class: strings.get(class_index).cloned().unwrap_or_default(),
        bitness,
        perm,
    })
}

/// The `$ segstrings` node's strings: a run of length-prefixed names.
fn seg_strings(node: Option<&super::netnode::Node>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(node) = node else {
        return out;
    };
    let Some(blob) = node.sup.get(&0) else {
        return out;
    };
    let mut pos = 0;
    while pos < blob.len() {
        let length = blob[pos] as usize;
        pos += 1;
        if length == 0 {
            break;
        }
        if pos + length > blob.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&blob[pos..pos + length]).into_owned());
        pos += length;
    }
    out
}

/// The processor and file facts of the `idainfo` blob: enough to say what
/// IDA loaded, read for both the pre-7.0 and the 7.0 layouts.
struct IdaInfo {
    procname: String,
    filetype: u16,
    lflags: u32,
}

impl IdaInfo {
    fn parse(bytes: &[u8]) -> Option<IdaInfo> {
        let mut r = InfoReader::new(bytes);
        let tag = r.take(3)?;
        let is_ida = tag == b"IDA";
        if tag == b"ida" {
            r.u8()?;
        } else if !is_ida {
            return None;
        }
        let version = r.u16()?;
        let procname_size = if version >= 700 && is_ida {
            Some(r.u8()? as usize)
        } else {
            None
        };
        let procname_len = procname_size.unwrap_or(if version < 700 { 8 } else { 16 });
        let procname = string_of(r.take(procname_len)?);
        let (lflags, filetype) = if version < 700 {
            let lflags = u32::from(r.u8()?);
            r.u8()?; // demnames
            let filetype = r.u16()?;
            (lflags, filetype)
        } else if is_ida {
            // The 7.0 "IDA" layout packs its numbers big-endian.
            let _genflags = r.u16_packed()?;
            let lflags = r.u32_packed()?;
            let _change = r.u32_packed()?;
            let filetype = r.u16_packed()?;
            (lflags, filetype)
        } else {
            let _genflags = r.u16()?;
            let lflags = r.u32()?;
            let _change = r.u32()?;
            let filetype = r.u16()?;
            (lflags, filetype)
        };
        Some(IdaInfo {
            procname,
            filetype,
            lflags,
        })
    }
}

/// A little-endian reader with the packed variants the 7.0 layout uses.
struct InfoReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> InfoReader<'a> {
    fn new(buf: &'a [u8]) -> InfoReader<'a> {
        InfoReader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u16_packed(&mut self) -> Option<u16> {
        let val = self.u8()?;
        if val == 0xFF {
            let b = self.take(2)?;
            Some(u16::from_be_bytes([b[0], b[1]]))
        } else if val & 0x80 != 0 {
            let next = self.u8()?;
            Some((u16::from(val & 0x3F) << 8) | u16::from(next))
        } else {
            Some(u16::from(val))
        }
    }

    fn u32_packed(&mut self) -> Option<u32> {
        let val = self.u8()?;
        if val == 0xFF {
            let b = self.take(4)?;
            Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        } else if val & 0xC0 == 0xC0 {
            let b1 = self.u8()?;
            let b2 = self.u8()?;
            let b3 = self.u8()?;
            Some(
                (u32::from(val & 0x1F) << 24)
                    | (u32::from(b1) << 16)
                    | (u32::from(b2) << 8)
                    | u32::from(b3),
            )
        } else if val & 0x80 != 0 {
            let next = self.u8()?;
            Some((u32::from(val & 0x3F) << 8) | u32::from(next))
        } else {
            Some(u32::from(val))
        }
    }
}
