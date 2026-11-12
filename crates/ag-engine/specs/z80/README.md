# The Z80 specification

Ghidra's SLEIGH specification of the Zilog Z80, compiled, carried inside the engine and read
through the SLEIGH runtime kuna ports, the way the ARM, MIPS, MSP430 and RISC-V specifications
under `../arm`, `../mips`, `../msp430` and `../riscv` are. The Z80 is an 8-bit microcontroller:
its registers are one byte, paired into sixteen-bit registers (`BC`, `DE`, `HL`, and `AF` the
accumulator with the flags), its address space is sixteen bits, and its instructions are one to
four bytes. Its condition flags live in the flag register `F` rather than in a register of their
own — the sign, zero, half-carry, parity/overflow and carry bits a compare, an arithmetic or a
load left — and a conditional jump tests those flags. There is no branch delay slot.

| File | What it is |
|---|---|
| `z80.sla` | The base Z80, little-endian: what `z80:LE:16:default` — the language the engine names for an ELF whose machine word is `220` (`EM_Z80`) — decodes under. |

The specification covers the whole instruction set: the eight-bit loads (`LD`), the sixteen-bit
loads and the exchange instructions (`EX`, `EXX`), the arithmetic and logic (`ADD`, `ADC`,
`SUB`, `SBC`, `AND`, `OR`, `XOR`, `CP`, `INC`, `DEC`), the rotates and shifts (`RLCA`, `RRCA`,
`RLA`, `RRA`, `SLA`, `SRA`, `SRL`, `RLC`, `RRC`, `RL`, `RR`), the bit set/reset/test (`BIT`,
`SET`, `RES`), the jumps and calls (`JP`, `JR`, `CALL`, `RET`, `RETI`, `RETN`, `RST`, `DJNZ`),
the stack (`PUSH`, `POP`), the index registers `IX` and `IY` and their halves, the block move
and search instructions (`LDIR`, `LDDR`, `CPIR`, `CPDR`) and the I/O and interrupt instructions
(`IN`, `OUT`, `IM`, `DI`, `EI`, `HALT`). The engine decodes it but does not lift it to pseudocode:
the listing and the graph are what it opens, as ARM and MIPS are (see [`crate::z80`]).

The file is the one kuna's own command line unpacks from the specifications it carries (into
`~/.cache/kuna/specs-9e2d082eab3527da/Ghidra/Processors/Z80/data/languages/`), compiled from the
source vendored in the kuna tree this workspace pins
(`specs/Ghidra/Processors/Z80/data/languages/z80.slaspec`) by kuna's SLEIGH compiler at the same
commit; it matches that cache byte for byte. To compile it again:

```sh
# in the kuna checkout cargo keeps (~/.cargo/git/checkouts/kuna-*/<rev>/decompiler)
cargo build --release -p kuna-slacomp
target/release/slacomp ../specs/Ghidra/Processors/Z80/data/languages/z80.slaspec
```

The specification is Ghidra's, under the Apache License, Version 2.0 (see `NOTICE` at the
root). Recompile it when the pinned kuna commit moves, so the runtime and the file agree.

The Z180, Z182 and Z8401x variants (`z180.sla` and its kin) are not carried: they are separate
processors, and an architecture is carried only with a fixture that exercises it. The fixture
here is the base Z80.
