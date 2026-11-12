# The 6502 specification

Ghidra's SLEIGH specification of the MOS 6502, compiled, carried inside the engine and read
through the SLEIGH runtime kuna ports, the way the ARM, MIPS, MSP430 and RISC-V specifications
under `../arm`, `../mips`, `../msp430` and `../riscv` are. The 6502 is an 8-bit microcontroller:
its accumulator `A` and index registers `X` and `Y` are one byte, its address space is sixteen
bits, so its program counter and its pointers are two bytes, and its instructions are one, two
or three bytes. Its condition flags live in the processor status register `P` rather than in a
register of their own — the negative, overflow, zero and carry bits a compare, an arithmetic or
a load left — and a branch tests those flags. There is no branch delay slot.

| File | What it is |
|---|---|
| `6502.sla` | The NMOS 6502, little-endian: what `6502:LE:16:default` — the language the engine names for an ELF whose machine word is `255` (`EM_65816`, the registered number of the 6502 family, the 8-bit core having no machine word of its own) — decodes under. |

The specification covers the whole documented instruction set: the loads and stores (`LDA`,
`LDX`, `LDY`, `STA`, `STX`, `STY`), the arithmetic and logic (`ADC`, `SBC`, `AND`, `ORA`,
`EOR`, `CMP`, `CPX`, `CPY`), the shifts and rotates (`ASL`, `LSR`, `ROL`, `ROR`), the increments
and decrements (`INC`, `DEC`, `INX`, `INY`, `DEX`, `DEY`), the stack and transfer instructions
(`PHA`, `PLA`, `PHP`, `PLP`, `TAX`, `TAY`, `TXA`, `TYA`, `TSX`, `TXS`), the branches (`BCC`,
`BCS`, `BEQ`, `BNE`, `BMI`, `BPL`, `BVC`, `BVS`), the jumps and calls (`JMP`, `JSR`, `RTS`,
`RTI`) and the flag instructions (`CLC`, `SEC`, `CLI`, `SEI`, `CLD`, `SED`, `CLV`, `NOP`,
`BRK`). The engine decodes it but does not lift it to pseudocode: the listing and the graph are
what it opens, as ARM and MIPS are (see [`crate::m6502`]).

The file is the one kuna's own command line unpacks from the specifications it carries (into
`~/.cache/kuna/specs-9e2d082eab3527da/Ghidra/Processors/6502/data/languages/`), compiled from the
source vendored in the kuna tree this workspace pins
(`specs/Ghidra/Processors/6502/data/languages/6502.slaspec`) by kuna's SLEIGH compiler at the same
commit; it matches that cache byte for byte. To compile it again:

```sh
# in the kuna checkout cargo keeps (~/.cargo/git/checkouts/kuna-*/<rev>/decompiler)
cargo build --release -p kuna-slacomp
target/release/slacomp ../specs/Ghidra/Processors/6502/data/languages/6502.slaspec
```

The specification is Ghidra's, under the Apache License, Version 2.0 (see `NOTICE` at the
root). Recompile it when the pinned kuna commit moves, so the runtime and the file agree.

The CMOS 65C02 variant (`65c02.sla`) is not carried: an architecture is carried only with a
fixture that exercises it, and the fixture here is the NMOS core.
