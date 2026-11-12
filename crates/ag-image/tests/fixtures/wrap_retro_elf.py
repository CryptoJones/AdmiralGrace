#!/usr/bin/env python3
"""Wrap a flat retro binary in a minimal ELF, for cores whose toolchains
do not emit one: cc65 links the 6502 to a raw image, sdldz80 links the Z80
to Intel HEX. The engine names these targets from the ELF machine word
(`EM_65816` for the 6502 family, `EM_Z80` for the Z80), so the wrapper
writes that word, one loadable `.text` at the link address, and a symbol
per function.

    wrap_retro_elf.py OUT.elf INPUT --base 0x4000 --machine 255 \
        --entry sum [--ihx] add=0x4000 sub=0x4004 ...

INPUT is raw bytes, or Intel HEX with --ihx. NAME=ADDR pairs become global
function symbols; --entry names the one the entry point is.
"""
import argparse
import struct
import sys


def read_image(path, base, ihx):
    if not ihx:
        with open(path, "rb") as handle:
            return base, handle.read()
    cells = {}
    with open(path, "r", encoding="ascii") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith(":"):
                continue
            raw = bytes.fromhex(line[1:])
            count, addr, kind = raw[0], (raw[1] << 8) | raw[2], raw[3]
            if kind == 0x00:
                for i in range(count):
                    cells[addr + i] = raw[4 + i]
            elif kind == 0x01:
                break
    if not cells:
        sys.exit("no data records in the Intel HEX file")
    low = min(cells)
    high = max(cells)
    image = bytes(cells.get(a, 0) for a in range(low, high + 1))
    return low, image


def build(base, machine, entry, code, symbols):
    # The section name table, then the symbol name table.
    shstr = b"\0.text\0.shstrtab\0.strtab\0.symtab\0"
    names = {".text": 1, ".shstrtab": 7, ".strtab": 17, ".symtab": 25}
    strtab = b"\0"
    offsets = {}
    for name, _ in symbols:
        offsets[name] = len(strtab)
        strtab += name.encode("ascii") + b"\0"

    # One Elf32_Sym per function, after the null symbol.
    symtab = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    for name, addr in symbols:
        symtab += struct.pack(
            "<IIIBBH", offsets[name], addr, 0, 0x12, 0, 1
        )  # STB_GLOBAL | STT_FUNC, in .text (section 1)

    code_off = 52 + 32  # the ELF header and one program header
    shstr_off = code_off + len(code)
    strtab_off = shstr_off + len(shstr)
    symtab_off = (strtab_off + len(strtab) + 3) & ~3
    shoff = (symtab_off + len(symtab) + 3) & ~3

    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01\x00" + b"\0" * 8,
        2,  # ET_EXEC
        machine,
        1,
        entry,
        52,  # e_phoff
        shoff,
        0,
        52,
        32,
        1,
        40,
        5,  # .text, .symtab, .shstrtab, .strtab and the null
        3,  # e_shstrndx
    )
    phdr = struct.pack(
        "<IIIIIIII", 1, code_off, base, base, len(code), len(code), 5, 0x1000
    )

    def shdr(name, kind, flags, addr, off, size, link, info, align, entsize):
        return struct.pack(
            "<IIIIIIIIII", name, kind, flags, addr, off, size, link, info, align, entsize
        )

    shdrs = b"".join(
        [
            shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            shdr(names[".text"], 1, 6, base, code_off, len(code), 0, 0, 4, 0),
            shdr(names[".symtab"], 2, 0, 0, symtab_off, len(symtab), 4, 1, 4, 16),
            shdr(names[".shstrtab"], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0),
            shdr(names[".strtab"], 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0),
        ]
    )

    out = bytearray(shoff + len(shdrs))
    out[0:52] = ehdr
    out[52:84] = phdr
    out[code_off:code_off + len(code)] = code
    out[shstr_off:shstr_off + len(shstr)] = shstr
    out[strtab_off:strtab_off + len(strtab)] = strtab
    out[symtab_off:symtab_off + len(symtab)] = symtab
    out[shoff:shoff + len(shdrs)] = shdrs
    return bytes(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out")
    parser.add_argument("input")
    parser.add_argument("--base", required=True, help="the link address, e.g. 0x4000")
    parser.add_argument("--machine", required=True, help="the ELF machine word, e.g. 255")
    parser.add_argument("--entry", required=True, help="the entry symbol's name")
    parser.add_argument("--ihx", action="store_true", help="read Intel HEX, not raw bytes")
    parser.add_argument("symbols", nargs="*", metavar="NAME=ADDR")
    args = parser.parse_args()

    base = int(args.base, 0)
    machine = int(args.machine, 0)
    low, code = read_image(args.input, base, args.ihx)
    if low != base:
        sys.exit(f"the image loads at {low:#x}, not the --base {base:#x}")

    symbols = []
    for pair in args.symbols:
        name, addr = pair.split("=", 1)
        symbols.append((name, int(addr, 0)))
    entry = dict(symbols).get(args.entry)
    if entry is None:
        sys.exit(f"the entry {args.entry!r} is not among the symbols")

    with open(args.out, "wb") as handle:
        handle.write(build(base, machine, entry, code, symbols))
    print(f"{args.out}: {len(code)} bytes at {base:#x}, machine {machine}, entry {args.entry}={entry:#x}")


if __name__ == "__main__":
    main()
