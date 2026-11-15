//! The IDA database container: the file header, the compressed sections,
//! and the B-tree index every name and comment is keyed in.
//!
//! A database opens with `IDA1` (32-bit) or `IDA2` (64-bit), a version
//! (4 or 6) and the offsets of six sections — `id0` the B-tree index,
//! `id1` the byte flags, `nam` the names, `seg`, `til` the local types and
//! `id2`. Each section is a compression byte, a length and the bytes,
//! zlib-compressed when the byte says 2. The index is a B-tree of
//! arbitrary byte keys and values; this walks it whole into a sorted map,
//! which the netnode layer reads.

use std::collections::BTreeMap;

use super::inflate;

/// Why a database did not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerError(pub String);

impl std::fmt::Display for ContainerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ContainerError {}

fn err<T>(message: impl Into<String>) -> Result<T, ContainerError> {
    Err(ContainerError(message.into()))
}

/// The six sections, in the order the header lists their offsets.
pub const SECTIONS: [&str; 6] = ["id0", "id1", "nam", "seg", "til", "id2"];

/// A whole database, read into memory: the index as a sorted map of key
/// to value, and the sections the netnode and type layers read.
#[derive(Debug, Clone)]
pub struct Database {
    /// 4 for `IDA1`, 8 for `IDA2`: the width of an address and a node id.
    pub wordsize: usize,
    /// The header version, 4 or 6.
    pub version: u16,
    /// The `id0` B-tree, every record in key order.
    pub index: BTreeMap<Vec<u8>, Vec<u8>>,
    /// The `id1` section: the flags of each byte, when present.
    pub id1: Vec<u8>,
    /// The `nam` section: the names table, when present.
    pub nam: Vec<u8>,
    /// The `til` section: the local type library, when present.
    pub til: Option<Vec<u8>>,
    /// How many records the index header says it holds.
    pub record_count: u32,
}

/// Read a database from its bytes.
pub fn parse(bytes: &[u8]) -> Result<Database, ContainerError> {
    let header = Header::parse(bytes)?;
    let mut sections: [Option<Vec<u8>>; 6] = Default::default();
    for (i, &offset) in header.offsets.iter().enumerate() {
        if offset == 0 {
            continue;
        }
        sections[i] = Some(section(bytes, offset as usize, header.version)?);
    }
    let id0 = sections[0]
        .take()
        .ok_or_else(|| ContainerError("database has no id0 index".into()))?;
    let btree = BTree::parse(&id0)?;
    let index = btree.walk()?;
    Ok(Database {
        wordsize: header.wordsize,
        version: header.version,
        record_count: btree.record_count,
        index,
        id1: sections[1].take().unwrap_or_default(),
        nam: sections[2].take().unwrap_or_default(),
        til: sections[4].take(),
    })
}

/// The file header: the signature, version and section offsets.
struct Header {
    wordsize: usize,
    version: u16,
    offsets: [u64; 6],
}

impl Header {
    fn parse(bytes: &[u8]) -> Result<Header, ContainerError> {
        if bytes.len() < 0x20 {
            return err("file is too short to be an IDA database");
        }
        let wordsize = match &bytes[0..4] {
            b"IDA1" => 4,
            b"IDA2" => 8,
            _ => return err("not an IDA database (missing IDA1/IDA2 signature)"),
        };
        let version = u16::from_le_bytes([bytes[0x1E], bytes[0x1F]]);
        if version != 4 && version != 6 {
            return err(format!("unsupported IDA header version {version}"));
        }
        let sig2 = u32::from_le_bytes([bytes[0x1A], bytes[0x1B], bytes[0x1C], bytes[0x1D]]);
        if sig2 != 0xAABB_CCDD {
            return err("bad IDA header signature");
        }
        // The offsets sit at fixed places that differ between the two
        // header versions; the order is id0, id1, nam, seg, til, id2.
        let offsets = if version <= 4 {
            [
                u32_at(bytes, 0x06),
                u32_at(bytes, 0x0A),
                u32_at(bytes, 0x0E),
                u32_at(bytes, 0x12),
                u32_at(bytes, 0x16),
                u32_at(bytes, 0x38),
            ]
        } else {
            [
                u64_at(bytes, 0x06),
                u64_at(bytes, 0x0E),
                u64_at(bytes, 0x20),
                u64_at(bytes, 0x28),
                u64_at(bytes, 0x30),
                u64_at(bytes, 0x4C),
            ]
        };
        Ok(Header {
            wordsize,
            version,
            offsets,
        })
    }
}

fn u32_at(bytes: &[u8], at: usize) -> u64 {
    if at + 4 > bytes.len() {
        return 0;
    }
    u64::from(u32::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
    ]))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    if at + 8 > bytes.len() {
        return 0;
    }
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
}

/// One section: a compression byte, a length, and the bytes — decompressed
/// when the method is zlib.
fn section(bytes: &[u8], at: usize, version: u16) -> Result<Vec<u8>, ContainerError> {
    if at >= bytes.len() {
        return err("section offset runs past the file");
    }
    let method = bytes[at];
    let (length, start) = if version <= 4 {
        let length = u32_at(bytes, at + 1) as usize;
        (length, at + 5)
    } else {
        let length = u64_at(bytes, at + 1) as usize;
        (length, at + 9)
    };
    let end = start
        .checked_add(length)
        .ok_or_else(|| ContainerError("section length overflows".into()))?;
    if end > bytes.len() {
        return err("section runs past the file");
    }
    let raw = &bytes[start..end];
    match method {
        0 => Ok(raw.to_vec()),
        2 => inflate::zlib(raw).map_err(|e| ContainerError(format!("section: {e}"))),
        other => err(format!("unknown section compression method {other}")),
    }
}

/// The `id0` B-tree index.
struct BTree<'a> {
    data: &'a [u8],
    page_size: usize,
    root_page: u32,
    record_count: u32,
    /// 2.0, 1.6 or 1.5, from the signature.
    version: f32,
}

impl<'a> BTree<'a> {
    fn parse(data: &'a [u8]) -> Result<BTree<'a>, ContainerError> {
        if data.len() < 20 {
            return err("id0 index is too short");
        }
        let page_size = u16::from_le_bytes([data[4], data[5]]) as usize;
        let root_page = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
        let record_count = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
        if page_size == 0 {
            return err("id0 page size is zero");
        }
        // The signature follows the fixed header at offset 19.
        let signature = &data[19..];
        let version = if signature.starts_with(b"B-tree v2") {
            2.0
        } else if signature.starts_with(b"B-tree v 1.6") {
            1.6
        } else if signature.starts_with(b"B-tree v 1.5") {
            1.5
        } else {
            return err("unrecognized id0 B-tree signature");
        };
        Ok(BTree {
            data,
            page_size,
            root_page,
            record_count,
            version,
        })
    }

    /// The size of one entry pointer in a page.
    fn sizeof_entry(&self) -> usize {
        match self.version {
            1.5 => 4,
            _ => 6,
        }
    }

    /// The bytes of one page.
    fn page(&self, number: u32) -> Result<&'a [u8], ContainerError> {
        let start = (number as usize)
            .checked_mul(self.page_size)
            .ok_or_else(|| ContainerError("page number overflows".into()))?;
        let end = start
            .checked_add(self.page_size)
            .ok_or_else(|| ContainerError("page size overflows".into()))?;
        if number == 0 || end > self.data.len() {
            return err(format!("page {number} runs past the index"));
        }
        Ok(&self.data[start..end])
    }

    /// Walk the whole tree in key order, collecting every record — leaf
    /// and branch alike, for the branch separators are records too.
    fn walk(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, ContainerError> {
        let mut out = BTreeMap::new();
        let mut depth = 0;
        self.walk_page(self.root_page, &mut out, &mut depth)?;
        Ok(out)
    }

    fn walk_page(
        &self,
        number: u32,
        out: &mut BTreeMap<Vec<u8>, Vec<u8>>,
        depth: &mut usize,
    ) -> Result<(), ContainerError> {
        *depth += 1;
        if *depth > 64 {
            return err("B-tree is too deep (a cycle?)");
        }
        let page = self.page(number)?;
        let header_size = if self.version >= 1.6 { 6 } else { 4 };
        let ppointer = if self.version >= 1.6 {
            u32::from_le_bytes([page[0], page[1], page[2], page[3]])
        } else {
            u32::from(u16::from_le_bytes([page[0], page[1]]))
        };
        let entry_count =
            u16::from_le_bytes([page[header_size - 2], page[header_size - 1]]) as usize;
        let is_leaf = ppointer == 0;
        let contents = &page[header_size..];
        let sizeof_entry = self.sizeof_entry();

        // A branch page's leftmost child holds the keys before the first
        // separator; walk it first.
        if !is_leaf {
            self.walk_page(ppointer, out, depth)?;
        }

        let mut previous_key: Vec<u8> = Vec::new();
        for i in 0..entry_count {
            let pointer_at = i
                .checked_mul(sizeof_entry)
                .ok_or_else(|| ContainerError("entry pointer overflows".into()))?;
            if pointer_at + sizeof_entry > contents.len() {
                return err("entry pointer runs past the page");
            }
            let pointer = &contents[pointer_at..pointer_at + sizeof_entry];
            let (common_prefix, data_offset, child) = self.read_pointer(pointer, is_leaf)?;
            if data_offset < sizeof_entry || data_offset > contents.len() {
                return err("entry data offset runs past the page");
            }
            let entry = &contents[data_offset - sizeof_entry..];
            let (key, value) = self.read_entry(entry, &previous_key, common_prefix, is_leaf)?;
            previous_key = key.clone();
            out.insert(key, value);
            // A branch separator is followed by the child holding the keys
            // greater than it.
            if !is_leaf {
                self.walk_page(child, out, depth)?;
            }
        }
        *depth -= 1;
        Ok(())
    }

    /// Read one entry pointer: the shared-prefix length (leaf), the offset
    /// of the entry data, and the child page (branch).
    fn read_pointer(
        &self,
        pointer: &[u8],
        is_leaf: bool,
    ) -> Result<(usize, usize, u32), ContainerError> {
        if is_leaf {
            let (common_prefix, offset_at) = match self.version {
                2.0 => (u16::from_le_bytes([pointer[0], pointer[1]]) as usize, 4),
                1.6 => (usize::from(pointer[0]), 2),
                _ => (usize::from(pointer[0]), 2),
            };
            let raw_offset = u16::from_le_bytes([pointer[offset_at], pointer[offset_at + 1]]);
            let offset = if self.version == 2.0 {
                usize::from(raw_offset)
            } else {
                usize::from(raw_offset) + 1
            };
            Ok((common_prefix, offset, 0))
        } else {
            let (child, offset_at) = match self.version {
                1.5 => (u32::from(u16::from_le_bytes([pointer[0], pointer[1]])), 2),
                _ => (
                    u32::from_le_bytes([pointer[0], pointer[1], pointer[2], pointer[3]]),
                    4,
                ),
            };
            let raw_offset = u16::from_le_bytes([pointer[offset_at], pointer[offset_at + 1]]);
            let offset = if self.version == 2.0 {
                usize::from(raw_offset)
            } else {
                usize::from(raw_offset) + 1
            };
            Ok((0, offset, child))
        }
    }

    /// Read one entry's key and value. A leaf key shares a prefix with the
    /// previous key in the page; a branch key stands alone.
    fn read_entry(
        &self,
        entry: &[u8],
        previous_key: &[u8],
        common_prefix: usize,
        is_leaf: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), ContainerError> {
        if entry.len() < 2 {
            return err("entry is too short");
        }
        let key_length = u16::from_le_bytes([entry[0], entry[1]]) as usize;
        let key_start = 2usize;
        let key_end = key_start
            .checked_add(key_length)
            .ok_or_else(|| ContainerError("key length overflows".into()))?;
        if key_end + 2 > entry.len() {
            return err("entry key runs past the page");
        }
        let mut key = if is_leaf {
            if common_prefix > previous_key.len() {
                return err("key prefix is longer than the previous key");
            }
            previous_key[..common_prefix].to_vec()
        } else {
            Vec::new()
        };
        key.extend_from_slice(&entry[key_start..key_end]);
        let value_length = u16::from_le_bytes([entry[key_end], entry[key_end + 1]]) as usize;
        let value_start = key_end + 2;
        let value_end = value_start
            .checked_add(value_length)
            .ok_or_else(|| ContainerError("value length overflows".into()))?;
        if value_end > entry.len() {
            return err("entry value runs past the page");
        }
        let value = entry[value_start..value_end].to_vec();
        Ok((key, value))
    }
}
