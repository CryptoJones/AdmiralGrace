"""Empty a Mach-O's symbol table in place — LC_SYMTAB's nsyms and strsize to 0,
and LC_DYSYMTAB's symbol counts with them — so the file keeps every load
command and section but names nothing, the way a shipped binary does. For
hosts without strip(1) for Mach-O."""
import struct, sys
src, dst = sys.argv[1:3]
d = bytearray(open(src, "rb").read())
magic = struct.unpack_from("<I", d, 0)[0]
assert magic == 0xFEEDFACF, "a 64-bit little-endian Mach-O"
ncmds = struct.unpack_from("<I", d, 16)[0]
off = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<II", d, off)
    if cmd == 0x2:  # LC_SYMTAB: cmd, cmdsize, symoff, nsyms, stroff, strsize
        struct.pack_into("<I", d, off + 12, 0)
        struct.pack_into("<I", d, off + 20, 0)
    if cmd == 0xb:  # LC_DYSYMTAB: the local, external and undefined counts
        for field in (12, 20, 28):  # nlocalsym, nextdefsym, nundefsym
            struct.pack_into("<I", d, off + field, 0)
    off += size
open(dst, "wb").write(d)
print(dst, "written: symbol table emptied")
