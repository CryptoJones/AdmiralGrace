//! A type library (`.til`): the header, the symbol and type buckets, and
//! the type records within them.
//!
//! A library opens with `IDATIL`, a format and flags, a title and a base
//! name, the compiler's byte sizes, then three buckets — symbols, types
//! and macros. A bucket is a count, a size and the bytes, zlib-compressed
//! when the ZIP flag is set. Each type record carries a name, an ordinal,
//! the packed type ([`super::types`] reads it), a comment, and the names
//! and comments of its fields or arguments.

use super::inflate;

/// Why a type library did not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TilError(pub String);

impl std::fmt::Display for TilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for TilError {}

fn err<T>(message: impl Into<String>) -> Result<T, TilError> {
    Err(TilError(message.into()))
}

/// The ZIP flag: the buckets are zlib-compressed.
const TIL_ZIP: u32 = 0x0001;
/// The ESI flag: extended sizeof info (short, long, long long).
const TIL_ESI: u32 = 0x0004;
/// The ORD flag: a type-ordinal count precedes the types bucket.
const TIL_ORD: u32 = 0x0010;
/// The SLD flag: sizeof(long double) is present.
const TIL_SLD: u32 = 0x0100;

/// A type library, read whole.
#[derive(Debug, Clone, Default)]
pub struct Til {
    /// The format version of the records.
    pub format: u32,
    /// The library flags.
    pub flags: u32,
    /// The title, e.g. "Local type definitions".
    pub title: String,
    /// The base library this one derives from, e.g. "gnulnx_x64".
    pub base: String,
    /// sizeof(int).
    pub size_i: u8,
    /// sizeof(bool).
    pub size_b: u8,
    /// sizeof(enum).
    pub size_e: u8,
    /// The default alignment.
    pub def_align: u8,
    /// sizeof(short), when the ESI flag is set.
    pub size_s: u8,
    /// sizeof(long), when the ESI flag is set.
    pub size_l: u8,
    /// sizeof(long long), when the ESI flag is set.
    pub size_ll: u8,
    /// sizeof(long double), when the SLD flag is set.
    pub size_ldbl: u8,
    /// The symbols, by ordinal.
    pub symbols: Vec<Symbol>,
    /// The types, in ordinal order.
    pub types: Vec<TypeRecord>,
}

/// One symbol of the library: an ordinal and the name it exports.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// The ordinal number.
    pub ordinal: u64,
    /// The symbol name.
    pub name: String,
}

/// One type record: its name, ordinal and the packed type bytes, with the
/// field or argument names and comments that ride beside them.
#[derive(Debug, Clone)]
pub struct TypeRecord {
    /// The name the type goes by.
    pub name: String,
    /// The ordinal number.
    pub ordinal: u64,
    /// The packed type, read by [`super::types`].
    pub type_info: Vec<u8>,
    /// The type's comment.
    pub comment: String,
    /// The field or argument names, in order.
    pub fields: Vec<String>,
    /// The field or argument comments, in order.
    pub field_comments: Vec<String>,
    /// The storage class.
    pub sclass: u8,
}

impl Til {
    /// Read a type library from its bytes.
    pub fn parse(bytes: &[u8]) -> Result<Til, TilError> {
        let mut c = Cursor::new(bytes);
        if c.take(6)? != b"IDATIL" {
            return err("not a type library (missing IDATIL signature)");
        }
        let format = c.u32()?;
        let flags = c.u32()?;
        let title = c.pstring()?;
        let base = c.pstring()?;
        let id = c.u8()?;
        let _ = id;
        let cm = c.u8()?;
        let _ = cm;
        let size_i = c.u8()?;
        let size_b = c.u8()?;
        let size_e = c.u8()?;
        let def_align = c.u8()?;
        let mut size_s = 0;
        let mut size_l = 0;
        let mut size_ll = 0;
        if flags & TIL_ESI != 0 {
            size_s = c.u8()?;
            size_l = c.u8()?;
            size_ll = c.u8()?;
        }
        let mut size_ldbl = 0;
        if flags & TIL_SLD != 0 {
            size_ldbl = c.u8()?;
        }
        let syms = bucket(&mut c, flags, format)?;
        if flags & TIL_ORD != 0 {
            let _ordinal_count = c.u32()?;
        }
        let types = bucket(&mut c, flags, format)?;
        // The macros bucket trails; a library may end before it is whole,
        // so its absence is not an error.
        let _macros = bucket(&mut c, flags, format).ok();

        let symbols = syms
            .into_iter()
            .map(|r| Symbol {
                ordinal: r.ordinal,
                name: r.name,
            })
            .collect();
        let mut types = types;
        types.sort_by_key(|t| t.ordinal);
        Ok(Til {
            format,
            flags,
            title,
            base,
            size_i,
            size_b,
            size_e,
            def_align,
            size_s,
            size_l,
            size_ll,
            size_ldbl,
            symbols,
            types,
        })
    }

    /// The type record a name names, when it exists.
    pub fn by_name(&self, name: &str) -> Option<&TypeRecord> {
        self.types.iter().find(|t| t.name == name)
    }

    /// The type record an ordinal names, when it exists.
    pub fn by_ordinal(&self, ordinal: u64) -> Option<&TypeRecord> {
        self.types.iter().find(|t| t.ordinal == ordinal)
    }
}

/// Read one bucket: a count, a size, the bytes (inflated when ZIP), and
/// the records within.
fn bucket(c: &mut Cursor, flags: u32, format: u32) -> Result<Vec<TypeRecord>, TilError> {
    let ndefs = c.u32()? as usize;
    let size = c.u32()? as usize;
    let compressed = flags & TIL_ZIP != 0;
    let clen = if compressed { c.u32()? as usize } else { size };
    let raw = c.take(clen)?;
    let buf = if compressed {
        inflate::zlib(raw).map_err(|e| TilError(format!("bucket: {e}")))?
    } else {
        raw.to_vec()
    };
    // A truncated bucket reads the records that are whole and stops.
    let mut bc = Cursor::new(&buf);
    let mut out = Vec::new();
    for _ in 0..ndefs {
        match record(&mut bc, format) {
            Ok(rec) => out.push(rec),
            Err(_) => break,
        }
    }
    Ok(out)
}

/// Read one type record.
fn record(c: &mut Cursor, format: u32) -> Result<TypeRecord, TilError> {
    let mut flags = c.u32()?;
    // Below format 0x12 the high bit is not the ordinal-width flag.
    if format < 0x12 {
        flags &= 0x7FFF_FFFF;
    }
    let wide_ordinal = flags & 0x8000_0000 != 0;
    let name = c.zstr()?;
    let ordinal = if wide_ordinal {
        c.u64()?
    } else {
        u64::from(c.u32()?)
    };
    let type_info = c.zbytes()?;
    let comment = c.zstr()?;
    let fields_buf = c.zbytes()?;
    let fieldcmts_buf = c.zbytes()?;
    let sclass = c.u8()?;
    Ok(TypeRecord {
        name,
        ordinal,
        type_info,
        comment,
        fields: length_prefixed(&fields_buf),
        field_comments: length_prefixed(&fieldcmts_buf),
        sclass,
    })
}

/// The length-prefixed strings of a fields buffer: each a length byte
/// (counting itself) then the characters; an empty one is dropped.
fn length_prefixed(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let length = buf[pos] as usize;
        pos += 1;
        if length == 0 {
            break;
        }
        let end = (pos + length - 1).min(buf.len());
        let text = String::from_utf8_lossy(&buf[pos..end]).into_owned();
        if !text.is_empty() {
            out.push(text);
        }
        pos += length - 1;
    }
    out
}

/// A cursor over the library bytes.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Cursor<'a> {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TilError> {
        if self.pos + n > self.buf.len() {
            return err("type library runs past its end");
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, TilError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, TilError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, TilError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A length-prefixed string: a length byte then the characters.
    fn pstring(&mut self) -> Result<String, TilError> {
        let length = self.u8()? as usize;
        let bytes = self.take(length)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    /// A NUL-terminated string.
    fn zstr(&mut self) -> Result<String, TilError> {
        Ok(String::from_utf8_lossy(&self.zbytes()?).into_owned())
    }

    /// NUL-terminated bytes.
    fn zbytes(&mut self) -> Result<Vec<u8>, TilError> {
        let start = self.pos;
        let end = self.buf[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| start + i)
            .ok_or_else(|| TilError("unterminated string in type library".into()))?;
        self.pos = end + 1;
        Ok(self.buf[start..end].to_vec())
    }
}
