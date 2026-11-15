//! Zlib decompression, written here so the IDA reader needs no dependency.
//!
//! IDA compresses the sections of a database and the buckets of a type
//! library with zlib (method 2). This reads the zlib wrapper of RFC 1950
//! and the DEFLATE stream of RFC 1951 within it: stored, fixed-Huffman and
//! dynamic-Huffman blocks, the length/distance codes and the extra bits
//! they carry. Only what IDA writes is read — a preset dictionary is
//! refused, and the Adler-32 trailer is checked.

/// Why a stream did not decompress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InflateError(pub String);

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for InflateError {}

fn err<T>(message: impl Into<String>) -> Result<T, InflateError> {
    Err(InflateError(message.into()))
}

/// The most bytes one stream may expand to: a guard against a corrupt or
/// hostile length, well above any section IDA writes.
const MAX_OUTPUT: usize = 512 * 1024 * 1024;

/// Decompress a zlib stream (RFC 1950): a two-byte header, the DEFLATE
/// data, and an Adler-32 checksum of the result.
pub fn zlib(input: &[u8]) -> Result<Vec<u8>, InflateError> {
    if input.len() < 6 {
        return err("zlib stream is too short");
    }
    let cmf = input[0];
    let flg = input[1];
    if cmf & 0x0F != 8 {
        return err("zlib compression method is not deflate");
    }
    if (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return err("zlib header check failed");
    }
    if flg & 0x20 != 0 {
        return err("zlib preset dictionary is not supported");
    }
    let out = deflate(&input[2..])?;
    // The trailer is the last four bytes of the whole stream; the deflate
    // reader stops at the final block, so find the checksum from the end.
    let want = u32::from_be_bytes([
        input[input.len() - 4],
        input[input.len() - 3],
        input[input.len() - 2],
        input[input.len() - 1],
    ]);
    if adler32(&out) != want {
        return err("zlib Adler-32 checksum mismatch");
    }
    Ok(out)
}

/// Decompress a raw DEFLATE stream (RFC 1951), with no zlib wrapper.
pub fn deflate(input: &[u8]) -> Result<Vec<u8>, InflateError> {
    let mut reader = BitReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let final_block = reader.bit()?;
        let kind = reader.bits(2)?;
        match kind {
            0 => stored(&mut reader, &mut out)?,
            1 => {
                let (lit, dist) = fixed_tables();
                block(&mut reader, &mut out, &lit, &dist)?;
            }
            2 => {
                let (lit, dist) = dynamic_tables(&mut reader)?;
                block(&mut reader, &mut out, &lit, &dist)?;
            }
            _ => return err("reserved DEFLATE block type"),
        }
        if out.len() > MAX_OUTPUT {
            return err("decompressed output is too large");
        }
        if final_block == 1 {
            break;
        }
    }
    Ok(out)
}

/// A stored block: skip to the byte boundary, read the length and its
/// complement, and copy the bytes.
fn stored(reader: &mut BitReader, out: &mut Vec<u8>) -> Result<(), InflateError> {
    reader.align();
    let len = reader.bits(16)? as usize;
    let nlen = reader.bits(16)? as usize;
    if len != (!nlen & 0xFFFF) {
        return err("stored block length check failed");
    }
    for _ in 0..len {
        out.push(reader.bits(8)? as u8);
    }
    Ok(())
}

/// One Huffman-coded block: symbols until the end-of-block code (256),
/// literals copied straight, length/distance pairs resolved against the
/// output so far.
fn block(
    reader: &mut BitReader,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
) -> Result<(), InflateError> {
    loop {
        let symbol = lit.decode(reader)?;
        match symbol {
            0..=255 => out.push(symbol as u8),
            256 => return Ok(()),
            257..=285 => {
                let (base, extra) = LENGTH_TABLE[(symbol - 257) as usize];
                let length = base as usize + reader.bits(extra)? as usize;
                let dsym = dist.decode(reader)?;
                if dsym >= 30 {
                    return err("invalid distance code");
                }
                let (dbase, dextra) = DIST_TABLE[dsym as usize];
                let distance = dbase as usize + reader.bits(dextra)? as usize;
                if distance == 0 || distance > out.len() {
                    return err("distance runs before the start of the output");
                }
                let start = out.len() - distance;
                for i in 0..length {
                    let byte = out[start + i];
                    out.push(byte);
                }
            }
            _ => return err("invalid length code"),
        }
        if out.len() > MAX_OUTPUT {
            return err("decompressed output is too large");
        }
    }
}

/// The length codes 257..285: a base length and the number of extra bits.
const LENGTH_TABLE: [(u16, u8); 29] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 1),
    (13, 1),
    (15, 1),
    (17, 1),
    (19, 2),
    (23, 2),
    (27, 2),
    (31, 2),
    (35, 3),
    (43, 3),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 4),
    (115, 4),
    (131, 5),
    (163, 5),
    (195, 5),
    (227, 5),
    (258, 0),
];

/// The distance codes 0..29: a base distance and the number of extra bits.
const DIST_TABLE: [(u16, u8); 30] = [
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 1),
    (7, 1),
    (9, 2),
    (13, 2),
    (17, 3),
    (25, 3),
    (33, 4),
    (49, 4),
    (65, 5),
    (97, 5),
    (129, 6),
    (193, 6),
    (257, 7),
    (385, 7),
    (513, 8),
    (769, 8),
    (1025, 9),
    (1537, 9),
    (2049, 10),
    (3073, 10),
    (4097, 11),
    (6145, 11),
    (8193, 12),
    (12289, 12),
    (16385, 13),
    (24577, 13),
];

/// A canonical Huffman decoder: the count of codes at each bit length and
/// the symbols in canonical order, walked one bit at a time.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    /// Build from the bit length of each symbol (0 means absent).
    fn new(lengths: &[u8]) -> Result<Huffman, InflateError> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            counts[len as usize] += 1;
        }
        counts[0] = 0;
        // A code of length 0..15; check the tree is not over-subscribed.
        let mut left = 1i32;
        for &count in counts.iter().skip(1) {
            left <<= 1;
            left -= i32::from(count);
            if left < 0 {
                return err("over-subscribed Huffman code");
            }
        }
        let mut offsets = [0u16; 16];
        for len in 1..15 {
            offsets[len + 1] = offsets[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len != 0 {
                symbols[offsets[len as usize] as usize] = symbol as u16;
                offsets[len as usize] += 1;
            }
        }
        Ok(Huffman { counts, symbols })
    }

    /// Read one symbol, most-significant bit of the code first.
    fn decode(&self, reader: &mut BitReader) -> Result<u16, InflateError> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for len in 1..16 {
            code |= reader.bit()? as i32;
            let count = i32::from(self.counts[len]);
            if code - first < count {
                return Ok(self.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        err("Huffman code is too long")
    }
}

/// The fixed Huffman tables of RFC 1951 §3.2.6.
fn fixed_tables() -> (Huffman, Huffman) {
    let mut lit = [0u8; 288];
    for (i, len) in lit.iter_mut().enumerate() {
        *len = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let dist = [5u8; 30];
    // The fixed tables are valid by construction.
    (
        Huffman::new(&lit).expect("fixed literal table"),
        Huffman::new(&dist).expect("fixed distance table"),
    )
}

/// The order the code-length code lengths are written in.
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Read the dynamic Huffman tables: the code-length code, then the
/// literal/length and distance code lengths it encodes.
fn dynamic_tables(reader: &mut BitReader) -> Result<(Huffman, Huffman), InflateError> {
    let hlit = reader.bits(5)? as usize + 257;
    let hdist = reader.bits(5)? as usize + 1;
    let hclen = reader.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return err("too many Huffman codes");
    }
    let mut cl_lengths = [0u8; 19];
    for &index in CL_ORDER.iter().take(hclen) {
        cl_lengths[index] = reader.bits(3)? as u8;
    }
    let cl = Huffman::new(&cl_lengths)?;
    let mut lengths = vec![0u8; hlit + hdist];
    let mut i = 0;
    while i < lengths.len() {
        let symbol = cl.decode(reader)?;
        match symbol {
            0..=15 => {
                lengths[i] = symbol as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return err("repeat code with no previous length");
                }
                let previous = lengths[i - 1];
                let repeat = 3 + reader.bits(2)? as usize;
                for _ in 0..repeat {
                    if i >= lengths.len() {
                        return err("repeat code runs past the code lengths");
                    }
                    lengths[i] = previous;
                    i += 1;
                }
            }
            17 => {
                let repeat = 3 + reader.bits(3)? as usize;
                i += repeat;
            }
            18 => {
                let repeat = 11 + reader.bits(7)? as usize;
                i += repeat;
            }
            _ => return err("invalid code-length symbol"),
        }
    }
    if i > lengths.len() {
        return err("code lengths run past the table");
    }
    let lit = Huffman::new(&lengths[..hlit])?;
    let dist = Huffman::new(&lengths[hlit..])?;
    Ok((lit, dist))
}

/// A least-significant-bit-first reader over the stream, as DEFLATE packs
/// its bits, with a byte-aligned window for the stored-block lengths.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> BitReader<'a> {
        BitReader {
            data,
            pos: 0,
            bit: 0,
        }
    }

    fn bit(&mut self) -> Result<u32, InflateError> {
        if self.pos >= self.data.len() {
            return err("unexpected end of DEFLATE stream");
        }
        let value = (self.data[self.pos] >> self.bit) & 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.pos += 1;
        }
        Ok(u32::from(value))
    }

    fn bits(&mut self, count: u8) -> Result<u32, InflateError> {
        let mut value = 0u32;
        for i in 0..count {
            value |= self.bit()? << i;
        }
        Ok(value)
    }

    fn align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.pos += 1;
        }
    }
}

/// The Adler-32 checksum of RFC 1950.
fn adler32(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler_known() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
    }

    #[test]
    fn round_trip_vectors() {
        // Vectors made with Python's zlib at several levels, including a
        // stored block; see tests/fixtures/ida/README.md.
        let raw = include_str!("../../tests/fixtures/ida/inflate_vectors.json");
        let vectors: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
        for vector in &vectors {
            let comp = hex(vector["comp"].as_str().unwrap());
            let plain = hex(vector["plain"].as_str().unwrap());
            let got = zlib(&comp).unwrap_or_else(|e| {
                panic!("{}: {e}", vector["name"].as_str().unwrap());
            });
            assert_eq!(got, plain, "{}", vector["name"].as_str().unwrap());
        }
    }

    #[test]
    fn rejects_bad_header() {
        assert!(zlib(&[0, 0, 0, 0, 0, 0]).is_err());
        assert!(zlib(&[]).is_err());
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
}
