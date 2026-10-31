//! The functions an image's unwind data names, symbols or none.
//!
//! An exception has to unwind the stack through every frame, so the linker
//! records the start and the end of nearly every function with how to
//! unwind it: an ELF's `.eh_frame` (and a Mach-O's `__eh_frame`) as DWARF
//! call-frame information, one entry per function; a PE's `.pdata` as a
//! table of `RUNTIME_FUNCTION`s, begin and end and unwind info, a function
//! sometimes split across chained entries; a Mach-O's `__unwind_info` as the
//! compact encoding, a two-level index of function starts whose sentinel is
//! the end of the last. A stripped binary keeps all of it, since it is read
//! at run time, so it is what names the functions no symbol does, and what
//! says where each one ends.
//!
//! Every count and every chain is bounded against a crafted file.

use std::collections::BTreeMap;

use gimli::{BaseAddresses, CieOrFde, EhFrame, EndianSlice, LittleEndian, UnwindSection};
use object::read::{Object, ObjectSection, ObjectSegment};

/// No real image has more functions in its unwind data: a bound on a
/// crafted table.
const MOST_FUNCTIONS: usize = 1 << 20;
/// No real function is split across more chained entries.
const LONGEST_CHAIN: usize = 16;

/// The functions the unwind data of the image `bytes` are names: each
/// start to the address past its last byte. Empty for an image without
/// any, and for any file that is not an ELF, a PE or a 64-bit Mach-O.
pub fn read(bytes: &[u8]) -> BTreeMap<u64, u64> {
    let mut functions = BTreeMap::new();
    let Ok(file) = object::File::parse(bytes) else {
        return functions;
    };
    if !file.is_little_endian() {
        return functions;
    }
    match file.format() {
        object::BinaryFormat::Elf => {
            eh_frame(&file, ".eh_frame", &mut functions);
        }
        object::BinaryFormat::Pe => {
            pdata(&file, &mut functions);
        }
        object::BinaryFormat::MachO if file.is_64() => {
            compact_unwind(&file, &mut functions);
            eh_frame(&file, "__eh_frame", &mut functions);
        }
        _ => {}
    }
    functions
}

/// Record a function, keeping the furthest end two records agree on.
fn note(functions: &mut BTreeMap<u64, u64>, start: u64, end: u64) {
    if end <= start || functions.len() >= MOST_FUNCTIONS {
        return;
    }
    let known = functions.entry(start).or_insert(end);
    if end > *known {
        *known = end;
    }
}

/// The frame description entries of the DWARF call-frame section `name`:
/// each covers one function, from its initial address for its length.
fn eh_frame(file: &object::File, name: &str, functions: &mut BTreeMap<u64, u64>) {
    let Some(section) = file.section_by_name(name) else {
        return;
    };
    let Ok(data) = section.data() else {
        return;
    };
    let mut eh_frame = EhFrame::new(data, LittleEndian);
    if !file.is_64() {
        eh_frame.set_address_size(4);
    }
    let mut bases = BaseAddresses::default().set_eh_frame(section.address());
    if let Some(text) = file.section_by_name(".text") {
        bases = bases.set_text(text.address());
    }
    if let Some(hdr) = file.section_by_name(".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(hdr.address());
    }
    let mut entries = eh_frame.entries(&bases);
    let mut seen = 0usize;
    while let Ok(Some(entry)) = entries.next() {
        seen += 1;
        if seen > MOST_FUNCTIONS {
            break;
        }
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(
            |section: &EhFrame<EndianSlice<LittleEndian>>, bases, offset| {
                section.cie_from_offset(bases, offset)
            },
        ) else {
            continue;
        };
        let start = fde.initial_address();
        let Some(end) = start.checked_add(fde.len()) else {
            continue;
        };
        note(functions, start, end);
    }
}

/// The `RUNTIME_FUNCTION`s of a PE's `.pdata`: begin and end as RVAs, and
/// the unwind info, whose chain leads a split function back to its start.
fn pdata(file: &object::File, functions: &mut BTreeMap<u64, u64>) {
    let Some(section) = file.section_by_name(".pdata") else {
        return;
    };
    let Ok(data) = section.data() else {
        return;
    };
    let base = file.relative_address_base();
    let read_u32 = |bytes: &[u8], at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
    };
    // The bytes at a virtual address, out of whichever section holds it.
    let at_rva = |rva: u32, len: usize| -> Option<&[u8]> {
        let address = base.wrapping_add(u64::from(rva));
        for section in file.sections() {
            let start = section.address();
            let Ok(data) = section.data() else {
                continue;
            };
            if address >= start && address.wrapping_sub(start) as usize + len <= data.len() {
                let offset = address.wrapping_sub(start) as usize;
                return data.get(offset..offset + len);
            }
        }
        None
    };
    for index in 0..(data.len() / 12).min(MOST_FUNCTIONS) {
        let entry = index * 12;
        let (Some(mut begin), Some(end), Some(mut info)) = (
            read_u32(data, entry),
            read_u32(data, entry + 4),
            read_u32(data, entry + 8),
        ) else {
            break;
        };
        if begin == 0 && end == 0 {
            continue;
        }
        let end = base.wrapping_add(u64::from(end));
        // A chained entry describes a piece of a function whose start is
        // the primary entry's, reached through the unwind info's flags.
        for _ in 0..LONGEST_CHAIN {
            let Some(header) = at_rva(info, 4) else {
                break;
            };
            let flags = header[0] >> 3;
            if flags & 0x4 == 0 {
                break;
            }
            let codes = usize::from(header[2]);
            let primary_at = info.wrapping_add(4 + (codes.div_ceil(2) * 4) as u32);
            let Some(primary) = at_rva(primary_at, 12) else {
                break;
            };
            let (Some(primary_begin), Some(primary_info)) =
                (read_u32(primary, 0), read_u32(primary, 8))
            else {
                break;
            };
            begin = primary_begin;
            info = primary_info;
        }
        note(functions, base.wrapping_add(u64::from(begin)), end);
    }
}

/// A Mach-O's `__unwind_info`: the compact encoding's two-level index of
/// function starts, relative to the image's text segment, with the final
/// index entry a sentinel at the end of the last function.
fn compact_unwind(file: &object::File, functions: &mut BTreeMap<u64, u64>) {
    let Some(section) = file.section_by_name("__unwind_info") else {
        return;
    };
    let Ok(data) = section.data() else {
        return;
    };
    // Offsets are from the image's start: the text segment's address.
    let Some(base) = file
        .segments()
        .find(|segment| segment.name().ok().flatten() == Some("__TEXT"))
        .map(|segment| segment.address())
    else {
        return;
    };
    let read_u32 = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
    };
    let read_u16 = |at: usize| -> Option<u16> {
        Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
    };
    if read_u32(0) != Some(1) {
        return;
    }
    let (Some(index_offset), Some(index_count)) = (read_u32(20), read_u32(24)) else {
        return;
    };
    let index_count = (index_count as usize).min(MOST_FUNCTIONS);
    let mut starts: Vec<u64> = Vec::new();
    let mut sentinel = None;
    for index in 0..index_count {
        let entry = index_offset as usize + index * 12;
        let (Some(function_offset), Some(page_offset)) = (read_u32(entry), read_u32(entry + 4))
        else {
            break;
        };
        if page_offset == 0 {
            // The sentinel: the end of the last function.
            sentinel = Some(base.wrapping_add(u64::from(function_offset)));
            break;
        }
        let page = page_offset as usize;
        match read_u32(page) {
            // A regular page: each entry its own function offset.
            Some(2) => {
                let (Some(entries_offset), Some(count)) = (read_u16(page + 4), read_u16(page + 6))
                else {
                    break;
                };
                for i in 0..usize::from(count) {
                    let Some(offset) = read_u32(page + usize::from(entries_offset) + i * 8) else {
                        break;
                    };
                    starts.push(base.wrapping_add(u64::from(offset)));
                }
            }
            // A compressed page: each entry an offset from the index entry's
            // in its low 24 bits.
            Some(3) => {
                let (Some(entries_offset), Some(count)) = (read_u16(page + 4), read_u16(page + 6))
                else {
                    break;
                };
                for i in 0..usize::from(count) {
                    let Some(entry) = read_u32(page + usize::from(entries_offset) + i * 4) else {
                        break;
                    };
                    let offset = u64::from(function_offset) + u64::from(entry & 0x00ff_ffff);
                    starts.push(base.wrapping_add(offset));
                }
            }
            _ => break,
        }
        if starts.len() > MOST_FUNCTIONS {
            break;
        }
    }
    starts.sort_unstable();
    starts.dedup();
    for (index, start) in starts.iter().enumerate() {
        let end = match starts.get(index + 1) {
            Some(next) => *next,
            None => match sentinel {
                Some(sentinel) => sentinel,
                None => continue,
            },
        };
        note(functions, *start, end);
    }
}
