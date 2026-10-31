"""Combine thin Mach-O files into one universal (fat) file, as lipo would:
a big-endian fat header, one fat_arch per slice, each slice at a page-aligned
offset (2^14, what lipo uses for arm64)."""
import struct, sys
CPUTYPES = {"x86_64": (0x01000007, 0x00000003), "arm64": (0x0100000C, 0x00000000), "i386": (0x7, 0x3), "arm": (0xC, 0x9)}
out, *pairs = sys.argv[1:]
slices = []
for pair in pairs:
    arch, path = pair.split("=", 1)
    slices.append((arch, open(path, "rb").read()))
align = 14
header = struct.pack(">II", 0xCAFEBABE, len(slices))
offset = 1 << align
entries = b""
body = b""
for arch, data in slices:
    cputype, cpusubtype = CPUTYPES[arch]
    entries += struct.pack(">IIIII", cputype, cpusubtype, offset, len(data), align)
    body += data
    pad = (-(offset + len(data))) % (1 << align)
    body += b"\0" * pad
    offset += len(data) + pad
head = header + entries
head += b"\0" * ((1 << align) - len(head))
open(out, "wb").write(head + body)
print(out, len(head + body), "bytes,", len(slices), "slices")
