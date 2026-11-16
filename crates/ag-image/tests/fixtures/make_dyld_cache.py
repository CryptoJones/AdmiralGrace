#!/usr/bin/env python3
"""Wrap thin Mach-O files into a synthetic dyld shared cache, as Apple's
cache builder does, for hosts without macOS: `make_dyld_cache.py OUT.cache
PATH=FILE [PATH=FILE ...]`.

Each image keeps its own segments' addresses, moved up by 256 MiB per image
so several fit in one cache without overlap. The segments are copied into
the cache file at page-aligned offsets, and the image's load commands are
rewritten the way the cache builder rewrites them: a segment's `fileoff` and
a section's `offset` become offsets into the cache file, and the linkedit
offsets (the symbol and string tables, the function starts, the export trie)
become offsets into the cache file's linkedit region. The cache header, the
mapping table and the image table are written as `dyld_cache_format.h` spells
them, matching the layout the `object` crate reads.

Only 64-bit little-endian Mach-O inputs are read (the x86-64 and arm64
fixtures); the cache magic is `dyld_v1  x86_64`.
"""
import struct
import sys

HEADER_SIZE = 0x200          # header region; mapping_offset says how big it is
MAPPING_SIZE = 56            # sizeof dyld_cache_mapping_and_slide_info
IMAGE_INFO_SIZE = 32         # sizeof dyld_cache_image_info
PAGE = 0x1000
IMAGE_SPACING = 0x10000000   # 256 MiB between images' address ranges

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | 0x80000000
LINKEDIT_DATA_CMDS = {
    0x1D, 0x1E, 0x26, 0x29, 0x33 | 0x80000000, 0x34 | 0x80000000, 0x36, 0x37,
}
N_TYPE = 0x0E
N_SECT = 0x0E


def align_up(value, to):
    return (value + to - 1) // to * to


def read_macho(data):
    magic, = struct.unpack_from("<I", data, 0)
    if magic != 0xFEEDFACF:
        raise SystemExit(f"input is not a 64-bit little-endian Mach-O (magic {magic:#x})")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    return ncmds, sizeofcmds


def commands(data, ncmds, sizeofcmds):
    """Yield (offset, cmd, cmdsize) for each load command."""
    off = 32
    end = 32 + sizeofcmds
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        yield off, cmd, cmdsize
        off += cmdsize
    assert off == end, "load commands do not fill sizeofcmds"


def build_image(data, delta, file_offset):
    """Copy one Mach-O's segments into the cache starting at file_offset.

    Returns (image_bytes, mappings, linkedit_fileoff) where image_bytes is the
    rewritten header+commands+segments, and mappings is a list of
    (vmaddr, vmsize, fileoff, prot) for the segments that hold bytes.
    """
    ncmds, sizeofcmds = read_macho(data)
    header_cmds = bytearray(data[: 32 + sizeofcmds])
    segments = []          # (cmd_off, vmaddr, vmsize, filesize, nsects)
    linkedit_orig_off = None
    linkedit_cmd_off = None
    for off, cmd, cmdsize in commands(data, ncmds, sizeofcmds):
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8 : off + 24].split(b"\0")[0]
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", data, off + 24)
            nsects, = struct.unpack_from("<I", data, off + 64)
            segments.append((off, segname, vmaddr, vmsize, fileoff, filesize, nsects))
            if segname == b"__LINKEDIT":
                linkedit_orig_off = fileoff
                linkedit_cmd_off = off

    # Lay the segments out in the cache file, page-aligned, after the header
    # region the caller reserved (file_offset points at the image's __TEXT).
    mappings = []
    content = bytearray()
    seg_new_off = {}
    cursor = file_offset
    for off, segname, vmaddr, vmsize, fileoff, filesize, nsects in segments:
        if filesize == 0:
            seg_new_off[off] = 0
            continue
        cursor = align_up(cursor, PAGE)
        seg_new_off[off] = cursor
        region = align_up(vmsize, PAGE)
        chunk = bytearray(region)
        chunk[:filesize] = data[fileoff : fileoff + filesize]
        # The cursor advances by the region; content is relative to file_offset.
        pad = cursor - file_offset - len(content)
        content.extend(b"\0" * pad)
        content.extend(chunk)
        prot = 5 if segname == b"__TEXT" else (3 if segname.startswith(b"__DATA") else 1)
        mappings.append((vmaddr + delta, region, cursor, prot))
        cursor += region
    image_end = cursor

    linkedit_new_off = seg_new_off.get(linkedit_cmd_off, 0)

    def rebase_linkedit(value):
        if value == 0 or linkedit_orig_off is None:
            return value
        return value - linkedit_orig_off + linkedit_new_off

    # Rewrite the load commands in the copied header.
    for off, cmd, cmdsize in commands(data, ncmds, sizeofcmds):
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8 : off + 24].split(b"\0")[0]
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", data, off + 24)
            nsects, = struct.unpack_from("<I", data, off + 64)
            struct.pack_into("<Q", header_cmds, off + 24, vmaddr + delta)   # vmaddr
            struct.pack_into("<Q", header_cmds, off + 40, seg_new_off[off]) # fileoff
            # vmsize, filesize unchanged.
            so = off + 72
            for _ in range(nsects):
                addr, = struct.unpack_from("<Q", data, so + 32)
                new_addr = addr + delta
                struct.pack_into("<Q", header_cmds, so + 32, new_addr)
                if filesize:
                    new_offset = seg_new_off[off] + (addr - vmaddr)
                    struct.pack_into("<I", header_cmds, so + 48, new_offset)
                so += 80
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", data, off + 8)
            struct.pack_into("<I", header_cmds, off + 8, rebase_linkedit(symoff))
            struct.pack_into("<I", header_cmds, off + 16, rebase_linkedit(stroff))
            # Rebase the defined symbols' addresses in the copied content.
            new_symoff = rebase_linkedit(symoff)
            rel = new_symoff - file_offset
            for i in range(nsyms):
                no = rel + i * 16
                n_type = content[no + 4]
                n_value, = struct.unpack_from("<Q", content, no + 8)
                if (n_type & N_TYPE) == N_SECT and n_value:
                    struct.pack_into("<Q", content, no + 8, n_value + delta)
        elif cmd == LC_DYSYMTAB:
            for field in (32, 40, 48, 56, 64, 72):  # tocoff..locreloff
                value, = struct.unpack_from("<I", data, off + field)
                struct.pack_into("<I", header_cmds, off + field, rebase_linkedit(value))
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            for field in (8, 16, 24, 32, 40):  # rebase/bind/weak/lazy/export off
                value, = struct.unpack_from("<I", data, off + field)
                struct.pack_into("<I", header_cmds, off + field, rebase_linkedit(value))
        elif cmd in LINKEDIT_DATA_CMDS:
            value, = struct.unpack_from("<I", data, off + 8)
            struct.pack_into("<I", header_cmds, off + 8, rebase_linkedit(value))

    # content starts at file_offset, where __TEXT (and thus the header) lives;
    # its first len(header_cmds) bytes are the original header+commands, which
    # the rewritten ones replace.
    image_bytes = bytes(header_cmds) + bytes(content[len(header_cmds):])
    return image_bytes, mappings, image_end


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    out = sys.argv[1]
    images = []
    for arg in sys.argv[2:]:
        path, _, file = arg.partition("=")
        if not file:
            raise SystemExit(f"expected PATH=FILE, got {arg!r}")
        images.append((path, open(file, "rb").read()))

    # Reserve the header, then lay each image's content out page-aligned.
    cursor = align_up(HEADER_SIZE, PAGE)
    built = []
    all_mappings = []
    for index, (path, data) in enumerate(images):
        delta = index * IMAGE_SPACING
        image_bytes, mappings, cursor = build_image(data, delta, cursor)
        all_mappings.extend(mappings)
        address = mappings[0][0] if mappings else 0
        built.append((path, data, image_bytes, address, cursor - len(image_bytes)))

    # Tables go in the header region's tail, after the fixed header.
    mappings_off = HEADER_SIZE
    images_off = mappings_off + len(all_mappings) * MAPPING_SIZE
    paths_off = images_off + len(built) * IMAGE_INFO_SIZE
    path_offsets = []
    paths = bytearray()
    for path, _, _, _, _ in built:
        path_offsets.append(paths_off + len(paths))
        paths.extend(path.encode() + b"\0")
    tables_end = paths_off + len(paths)
    if tables_end > cursor:
        raise SystemExit("tables overlap image content; reserve more header space")

    cache = bytearray(cursor)
    # Header.
    # Field offsets as object's dyld_cache_header spells them.
    cache[0:16] = b"dyld_v1  x86_64\0"
    struct.pack_into("<I", cache, 0x10, HEADER_SIZE)        # mapping_offset (header size)
    struct.pack_into("<I", cache, 0x14, len(all_mappings))  # mapping_count
    struct.pack_into("<I", cache, 0x138, mappings_off)      # mapping_with_slide_offset
    struct.pack_into("<I", cache, 0x13C, len(all_mappings)) # mapping_with_slide_count
    struct.pack_into("<Q", cache, 0xE0, built[0][3])        # shared_region_start
    struct.pack_into("<I", cache, 0x1C0, images_off)        # images_offset
    struct.pack_into("<I", cache, 0x1C4, len(built))        # images_count
    cache[0x58:0x68] = bytes(range(16))                     # uuid
    # Mappings (dyld_cache_mapping_and_slide_info).
    for i, (address, size, fileoff, prot) in enumerate(all_mappings):
        mo = mappings_off + i * MAPPING_SIZE
        struct.pack_into("<QQQ", cache, mo, address, size, fileoff)
        struct.pack_into("<QQQ", cache, mo + 24, 0, 0, 0)   # slide info offset/size, flags
        struct.pack_into("<II", cache, mo + 48, prot, prot) # max_prot, init_prot
    # Image table (dyld_cache_image_info) and paths.
    for i, (path, data, image_bytes, address, content_off) in enumerate(built):
        io = images_off + i * IMAGE_INFO_SIZE
        struct.pack_into("<QQQ", cache, io, address, 0, 0)  # address, mod_time, inode
        struct.pack_into("<II", cache, io + 24, path_offsets[i], 0)
        cache[content_off : content_off + len(image_bytes)] = image_bytes
    cache[paths_off : paths_off + len(paths)] = paths

    with open(out, "wb") as handle:
        handle.write(cache)
    print(f"wrote {out}: {len(built)} image(s), {len(cache)} bytes")
    for path, _, _, address, _ in built:
        print(f"  {address:#x}  {path}")


if __name__ == "__main__":
    main()