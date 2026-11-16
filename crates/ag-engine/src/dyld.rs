//! Apple's dyld shared cache: many dylibs mapped together in one file (or a
//! main file and its subcaches), the way the system loads them at run time.
//!
//! The cache is not an image the loader reads whole: it is a container of
//! images, each a Mach-O whose segments lie at the cache's unslid addresses.
//! This module lists the images and lifts one out into a standalone Mach-O
//! the engine reads as any other — the way `dsc_extractor` does, copying each
//! segment's bytes out of the cache mappings and rewriting the file offsets
//! the load commands carry to the new file's layout. The pointers the cache
//! holds are left as they are: they already name the unslid addresses the
//! extracted image keeps, so the image reads consistently at the load
//! addresses the cache states.
//!
//! The parsing of the header, the mappings and the image table is
//! [`object::read::macho::DyldCache`]'s; this module is the extraction.

use anyhow::{Context, Result};
use object::macho;
use object::read::macho::{DyldCache, DyldCacheImage, MachHeader, Section as _, Segment as _};
use object::{pod, Endianness};

/// One image (a dylib) the shared cache holds: the path it was built from,
/// and the unslid address its Mach-O header lies at in the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldImage {
    /// The install path the cache names the image by, such as
    /// `/usr/lib/system/libsystem_kernel.dylib`.
    pub path: String,
    /// The unslid address of the image's Mach-O header in the cache.
    pub address: u64,
}

/// Whether `bytes` are a dyld shared cache, by the magic its header carries.
pub fn is_dyld_cache(bytes: &[u8]) -> bool {
    dyld_images(bytes).is_some()
}

/// The images the shared cache `bytes` holds, in the cache's order; `None`
/// for any file that is not a cache.
///
/// Only the main cache file is read: the image table lives in it, so the
/// images can be listed without the subcaches that hold their bytes.
pub fn dyld_images(bytes: &[u8]) -> Option<Vec<DyldImage>> {
    let header = macho::DyldCacheHeader::<Endianness>::parse(bytes).ok()?;
    let (_arch, endian) = header.parse_magic().ok()?;
    let images = header.images(endian, bytes).ok()?;
    let mut listed = Vec::with_capacity(images.len());
    for info in images {
        let path = info.path(endian, bytes).ok()?;
        let path = std::str::from_utf8(path).ok()?;
        listed.push(DyldImage {
            path: path.to_string(),
            address: info.address.get(endian),
        });
    }
    Some(listed)
}

/// The image `selector` names among `images`: its full install path, its
/// basename (`libsystem_kernel.dylib`), or its position counted from 0 —
/// the first of that name when two share it.
pub fn resolve_dyld_image<'a>(images: &'a [DyldImage], selector: &str) -> Option<&'a DyldImage> {
    let wanted = selector.trim();
    images
        .iter()
        .find(|image| image.path == wanted)
        .or_else(|| {
            images.iter().find(|image| {
                image
                    .path
                    .rsplit('/')
                    .next()
                    .is_some_and(|base| base == wanted)
            })
        })
        .or_else(|| {
            wanted
                .parse::<usize>()
                .ok()
                .and_then(|index| images.get(index))
        })
}

/// Lift the image `selector` names out of the shared cache `bytes` and its
/// `subcaches` (the main file's siblings, in the order the header names
/// them), as a standalone Mach-O: the chosen image's identity, and the bytes
/// the engine reads as any other Mach-O.
pub fn extract(
    bytes: &[u8],
    subcaches: &[Vec<u8>],
    selector: &str,
) -> Result<(DyldImage, Vec<u8>)> {
    let images = dyld_images(bytes).context("the file is not a dyld shared cache")?;
    let chosen = resolve_dyld_image(&images, selector).with_context(|| {
        format!(
            "the cache has no image {selector:?}; it holds {} image{}",
            images.len(),
            if images.len() == 1 { "" } else { "s" }
        )
    })?;
    let refs: Vec<&[u8]> = subcaches.iter().map(Vec::as_slice).collect();
    let cache = DyldCache::parse(bytes, &refs).context("reading the dyld shared cache")?;
    let image = cache
        .images()
        .find(|image| image.info().address.get(cache.endianness()) == chosen.address)
        .context("the chosen image is not in the cache's mappings")?;
    let endian = cache.endianness();
    let (data, offset) = image
        .image_data_and_offset()
        .context("the image's header is not in any cache mapping")?;
    let magic = data
        .get(offset as usize..offset as usize + 4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .context("the image's header runs past the end of its subcache")?;
    let extracted = match magic {
        macho::MH_MAGIC_64 | macho::MH_CIGAM_64 => {
            extract_width::<macho::MachHeader64<Endianness>>(&cache, &image, endian)?
        }
        macho::MH_MAGIC | macho::MH_CIGAM => {
            extract_width::<macho::MachHeader32<Endianness>>(&cache, &image, endian)?
        }
        _ => anyhow::bail!("the image at {:#x} is not a Mach-O", chosen.address),
    };
    Ok((chosen.clone(), extracted))
}

/// A segment's place in the extraction: where its command stands in the
/// header, the addresses and sizes it states, and where its bytes land in
/// the new file.
struct SegmentPlan {
    /// The command's offset in the cache file the header lies in.
    command: usize,
    vmaddr: u64,
    filesize: u64,
    nsects: u32,
    /// The command's size, so the sections after it can be found.
    cmdsize: usize,
    is_text: bool,
    is_linkedit: bool,
    /// Where the segment's bytes land in the new file.
    new_offset: u64,
    new_size: u64,
}

/// A linkedit offset field to rebase: where it stands in the cache file, and
/// the size of the table it names (to reckon how far the linkedit goes).
struct LinkeditField {
    offset: usize,
    size: u64,
}

/// The page size segments are aligned to in the extracted file, as the cache
/// maps them: 4 KiB, the page of every architecture the cache is built for
/// here. (arm64's 16 KiB pages round up to the same layout for the fixtures.)
const PAGE: u64 = 0x1000;

fn align_up(value: u64, to: u64) -> u64 {
    value.div_ceil(to) * to
}

/// Lift one image out of the cache, for a Mach-O of the width `Mach` names.
fn extract_width<Mach>(
    cache: &DyldCache<'_, Endianness>,
    image: &DyldCacheImage<'_, '_, Endianness>,
    endian: Endianness,
) -> Result<Vec<u8>>
where
    Mach: MachHeader<Endian = Endianness>,
    Mach::Segment: SegmentPatch,
    Mach::Section: SectionPatch,
{
    let (data, header_offset) = image.image_data_and_offset()?;
    let ho = header_offset as usize;
    let header = Mach::parse(data, header_offset)?;
    let header_size = std::mem::size_of::<Mach>();
    let sizeofcmds = header.sizeofcmds(endian) as usize;
    let ncmds = header.ncmds(endian);
    let address = image.info().address.get(endian);
    let nlist_size = std::mem::size_of::<Mach::Nlist>() as u64;

    // Walk the load commands once, noting each segment and each linkedit
    // offset field, with where it stands in the cache file.
    let mut segments: Vec<SegmentPlan> = Vec::new();
    let mut fields: Vec<LinkeditField> = Vec::new();
    let mut commands = header.load_commands(endian, data, header_offset)?;
    let mut off = ho + header_size;
    for _ in 0..ncmds {
        let command = commands
            .next()?
            .context("a load command runs past the header")?;
        let cmd = command.cmd();
        let cmdsize = command.cmdsize() as usize;
        if let Some((segment, _)) = Mach::Segment::from_command(command)? {
            let vmaddr: u64 = segment.vmaddr(endian).into();
            let filesize: u64 = segment.filesize(endian).into();
            segments.push(SegmentPlan {
                command: off,
                vmaddr,
                filesize,
                nsects: segment.nsects(endian),
                cmdsize,
                is_text: vmaddr == address,
                is_linkedit: segment.name() == macho::SEG_LINKEDIT.as_bytes(),
                new_offset: 0,
                new_size: 0,
            });
        }
        collect_linkedit_fields(cmd, off, command, endian, nlist_size, &mut fields)?;
        off += cmdsize;
    }

    let text = segments
        .iter()
        .find(|segment| segment.is_text)
        .context("the image has no segment at its header address")?;
    let text_size = text.filesize;
    anyhow::ensure!(
        text_size >= (header_size + sizeofcmds) as u64,
        "the image's text segment is too short for its header"
    );

    // The linkedit's bytes start where its segment maps to, and go as far as
    // the furthest table its load commands name.
    let linkedit = segments.iter().find(|segment| segment.is_linkedit);
    let linkedit_base = match linkedit {
        Some(segment) => cache
            .data_and_offset_for_address(segment.vmaddr)
            .map(|(_, offset)| offset)
            .context("the image's linkedit is not in any cache mapping")?,
        None => fields
            .iter()
            .map(|field| read_u32(data, field.offset, endian) as u64)
            .filter(|value| *value != 0)
            .min()
            .unwrap_or(0),
    };
    let linkedit_end = fields
        .iter()
        .map(|field| {
            let value = read_u32(data, field.offset, endian) as u64;
            if value == 0 {
                0
            } else {
                value + field.size
            }
        })
        .max()
        .unwrap_or(linkedit_base)
        .max(linkedit_base);

    // The new file: the text segment first (it carries the header and load
    // commands), then the other segments, then the linkedit, each aligned.
    let text_bytes = data
        .get(ho..ho + text_size as usize)
        .context("the image's text segment runs past the end of its subcache")?;
    let mut out = text_bytes.to_vec();
    for segment in &mut segments {
        if segment.is_text {
            segment.new_offset = 0;
            segment.new_size = text_size;
            continue;
        }
        if segment.is_linkedit {
            let new_offset = align_up(out.len() as u64, PAGE);
            out.resize(new_offset as usize, 0);
            let size = linkedit_end - linkedit_base;
            let (file, _) = cache
                .data_and_offset_for_address(segment.vmaddr)
                .context("the image's linkedit is not in any cache mapping")?;
            let bytes = file
                .get(linkedit_base as usize..linkedit_end as usize)
                .context("the image's linkedit runs past the end of its subcache")?;
            out.extend_from_slice(bytes);
            segment.new_offset = new_offset;
            segment.new_size = size;
            continue;
        }
        if segment.filesize == 0 {
            // A segment with no bytes in the file (__PAGEZERO): kept as it
            // stands, mapping nothing.
            continue;
        }
        let new_offset = align_up(out.len() as u64, PAGE);
        out.resize(new_offset as usize, 0);
        let (file, file_offset) = cache
            .data_and_offset_for_address(segment.vmaddr)
            .with_context(|| {
                format!(
                    "the segment at {:#x} is not in any cache mapping",
                    segment.vmaddr
                )
            })?;
        let start = file_offset as usize;
        let end = start + segment.filesize as usize;
        let bytes = file
            .get(start..end)
            .context("a segment runs past the end of its subcache")?;
        out.extend_from_slice(bytes);
        segment.new_offset = new_offset;
        segment.new_size = segment.filesize;
    }
    let linkedit_new_offset = segments
        .iter()
        .find(|segment| segment.is_linkedit)
        .map(|segment| segment.new_offset)
        .unwrap_or(0);

    // Rewrite the header's load commands to the new file's layout: each
    // segment's file offset and size, each section's offset (reckoned from
    // its address, never trusted as the cache spelled it), and each linkedit
    // offset, rebased from the cache's linkedit to the new file's.
    for segment in &segments {
        let at = segment.command - ho;
        let (patch, _) = pod::from_bytes_mut::<Mach::Segment>(&mut out[at..])
            .map_err(|_| anyhow::anyhow!("a segment command runs past the header"))?;
        patch.patch_file(endian, segment.new_offset, segment.new_size);
        let sections_at =
            at + segment.cmdsize - segment.nsects as usize * std::mem::size_of::<Mach::Section>();
        for index in 0..segment.nsects as usize {
            let soff = sections_at + index * std::mem::size_of::<Mach::Section>();
            let (section, _) = pod::from_bytes_mut::<Mach::Section>(&mut out[soff..])
                .map_err(|_| anyhow::anyhow!("a section runs past the header"))?;
            let addr: u64 = section.addr(endian).into();
            let offset = if section.is_zerofill(endian) {
                0
            } else {
                (segment.new_offset + addr.saturating_sub(segment.vmaddr)) as u32
            };
            section.patch_offset(endian, offset);
        }
    }
    for field in &fields {
        let at = field.offset - ho;
        let value = read_u32(&out, at, endian);
        if value != 0 {
            let rebased = (value as u64).saturating_sub(linkedit_base) + linkedit_new_offset;
            write_u32(&mut out, at, endian, rebased as u32);
        }
    }
    Ok(out)
}

/// Note the linkedit offset fields a load command carries: the symbol and
/// string tables, the dynamic symbol table's tables, the dyld info's tables,
/// and the linkedit data commands (function starts, data in code, the export
/// trie, chained fixups, the code signature and the rest).
fn collect_linkedit_fields(
    cmd: u32,
    off: usize,
    command: object::read::macho::LoadCommandData<'_, Endianness>,
    endian: Endianness,
    nlist_size: u64,
    fields: &mut Vec<LinkeditField>,
) -> Result<()> {
    use std::mem::offset_of;
    type Symtab = macho::SymtabCommand<Endianness>;
    type Dysymtab = macho::DysymtabCommand<Endianness>;
    type DyldInfo = macho::DyldInfoCommand<Endianness>;
    type LinkeditData = macho::LinkeditDataCommand<Endianness>;
    let mut note = |field_off: usize, size: u64| {
        fields.push(LinkeditField {
            offset: off + field_off,
            size,
        });
    };
    match cmd {
        macho::LC_SYMTAB => {
            let symtab = command.data::<Symtab>()?;
            note(
                offset_of!(Symtab, symoff),
                symtab.nsyms.get(endian) as u64 * nlist_size,
            );
            note(
                offset_of!(Symtab, stroff),
                symtab.strsize.get(endian) as u64,
            );
        }
        macho::LC_DYSYMTAB => {
            let dysymtab = command.data::<Dysymtab>()?;
            note(
                offset_of!(Dysymtab, tocoff),
                dysymtab.ntoc.get(endian) as u64 * 8,
            );
            note(
                offset_of!(Dysymtab, modtaboff),
                dysymtab.nmodtab.get(endian) as u64 * 12,
            );
            note(
                offset_of!(Dysymtab, extrefsymoff),
                dysymtab.nextrefsyms.get(endian) as u64 * 4,
            );
            note(
                offset_of!(Dysymtab, indirectsymoff),
                dysymtab.nindirectsyms.get(endian) as u64 * 4,
            );
            note(
                offset_of!(Dysymtab, extreloff),
                dysymtab.nextrel.get(endian) as u64 * 8,
            );
            note(
                offset_of!(Dysymtab, locreloff),
                dysymtab.nlocrel.get(endian) as u64 * 8,
            );
        }
        macho::LC_DYLD_INFO | macho::LC_DYLD_INFO_ONLY => {
            let info = command.data::<DyldInfo>()?;
            note(
                offset_of!(DyldInfo, rebase_off),
                info.rebase_size.get(endian) as u64,
            );
            note(
                offset_of!(DyldInfo, bind_off),
                info.bind_size.get(endian) as u64,
            );
            note(
                offset_of!(DyldInfo, weak_bind_off),
                info.weak_bind_size.get(endian) as u64,
            );
            note(
                offset_of!(DyldInfo, lazy_bind_off),
                info.lazy_bind_size.get(endian) as u64,
            );
            note(
                offset_of!(DyldInfo, export_off),
                info.export_size.get(endian) as u64,
            );
        }
        macho::LC_CODE_SIGNATURE
        | macho::LC_SEGMENT_SPLIT_INFO
        | macho::LC_FUNCTION_STARTS
        | macho::LC_DATA_IN_CODE
        | macho::LC_DYLD_EXPORTS_TRIE
        | macho::LC_DYLD_CHAINED_FIXUPS
        | macho::LC_ATOM_INFO
        | macho::LC_FUNCTION_VARIANTS => {
            let linkedit = command.data::<LinkeditData>()?;
            note(
                offset_of!(LinkeditData, dataoff),
                linkedit.datasize.get(endian) as u64,
            );
        }
        _ => {}
    }
    Ok(())
}

fn read_u32(data: &[u8], offset: usize, endian: Endianness) -> u32 {
    let bytes: [u8; 4] = data[offset..offset + 4].try_into().expect("four bytes");
    if endian == Endianness::Little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    }
}

fn write_u32(data: &mut [u8], offset: usize, endian: Endianness, value: u32) {
    let bytes = if endian == Endianness::Little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    data[offset..offset + 4].copy_from_slice(&bytes);
}

/// Set a segment command's file offset and size to the extracted file's.
trait SegmentPatch: object::read::macho::Segment<Endian = Endianness> {
    fn patch_file(&mut self, endian: Endianness, fileoff: u64, filesize: u64);
}

impl SegmentPatch for macho::SegmentCommand64<Endianness> {
    fn patch_file(&mut self, endian: Endianness, fileoff: u64, filesize: u64) {
        self.fileoff.set(endian, fileoff);
        self.filesize.set(endian, filesize);
    }
}

impl SegmentPatch for macho::SegmentCommand32<Endianness> {
    fn patch_file(&mut self, endian: Endianness, fileoff: u64, filesize: u64) {
        self.fileoff.set(endian, fileoff as u32);
        self.filesize.set(endian, filesize as u32);
    }
}

/// Set a section's file offset, and say whether it is zero-fill (no bytes in
/// the file).
trait SectionPatch: object::read::macho::Section<Endian = Endianness> {
    fn patch_offset(&mut self, endian: Endianness, offset: u32);
    fn is_zerofill(&self, endian: Endianness) -> bool;
}

impl SectionPatch for macho::Section64<Endianness> {
    fn patch_offset(&mut self, endian: Endianness, offset: u32) {
        self.offset.set(endian, offset);
    }
    fn is_zerofill(&self, endian: Endianness) -> bool {
        matches!(
            self.section_type(endian),
            macho::S_ZEROFILL | macho::S_GB_ZEROFILL | macho::S_THREAD_LOCAL_ZEROFILL
        )
    }
}

impl SectionPatch for macho::Section32<Endianness> {
    fn patch_offset(&mut self, endian: Endianness, offset: u32) {
        self.offset.set(endian, offset);
    }
    fn is_zerofill(&self, endian: Endianness) -> bool {
        matches!(
            self.section_type(endian),
            macho::S_ZEROFILL | macho::S_GB_ZEROFILL | macho::S_THREAD_LOCAL_ZEROFILL
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn images() -> Vec<DyldImage> {
        vec![
            DyldImage {
                path: "/usr/lib/system/libsystem_kernel.dylib".to_string(),
                address: 0x1000,
            },
            DyldImage {
                path: "/usr/lib/libobjc.A.dylib".to_string(),
                address: 0x2000,
            },
        ]
    }

    #[test]
    fn an_image_is_chosen_by_path_basename_or_position() {
        let listed = images();
        // The full install path.
        assert_eq!(
            resolve_dyld_image(&listed, "/usr/lib/libobjc.A.dylib").map(|i| i.address),
            Some(0x2000)
        );
        // The basename alone.
        assert_eq!(
            resolve_dyld_image(&listed, "libsystem_kernel.dylib").map(|i| i.address),
            Some(0x1000)
        );
        // The position, counted from 0, with surrounding space trimmed.
        assert_eq!(
            resolve_dyld_image(&listed, " 1 ").map(|i| i.address),
            Some(0x2000)
        );
        // A name or position the cache lacks.
        assert!(resolve_dyld_image(&listed, "libmissing.dylib").is_none());
        assert!(resolve_dyld_image(&listed, "2").is_none());
    }

    #[test]
    fn the_first_of_a_name_wins_when_two_share_it() {
        let listed = vec![
            DyldImage {
                path: "/a/libfoo.dylib".to_string(),
                address: 0x10,
            },
            DyldImage {
                path: "/b/libfoo.dylib".to_string(),
                address: 0x20,
            },
        ];
        assert_eq!(
            resolve_dyld_image(&listed, "libfoo.dylib").map(|i| i.address),
            Some(0x10)
        );
        // The full path still tells them apart.
        assert_eq!(
            resolve_dyld_image(&listed, "/b/libfoo.dylib").map(|i| i.address),
            Some(0x20)
        );
    }

    #[test]
    fn a_file_that_is_not_a_cache_lists_no_images() {
        assert!(dyld_images(&[]).is_none());
        assert!(dyld_images(b"\x7fELF not a cache").is_none());
        // A Mach-O magic is not a cache magic.
        assert!(dyld_images(&0xfeed_facfu32.to_le_bytes()).is_none());
        assert!(!is_dyld_cache(b"dyld_v1"));
    }
}
