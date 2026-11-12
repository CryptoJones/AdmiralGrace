# The MSP430 specification

Ghidra's SLEIGH specification of the TI MSP430, compiled, carried inside the engine and read
through the SLEIGH runtime kuna ports, the way the ARM, MIPS and RISC-V specifications under
`../arm`, `../mips` and `../riscv` are. The MSP430 is a 16-bit microcontroller: its registers
and its addresses are two bytes, its instructions are one, two or three halfwords, and its
condition flags live in the status register `SR` (`R2`) rather than in a register of their own.
A branch tests those flags — the zero, carry, sign and overflow bits a `cmp`, `sub` or `add`
left — so the lift reads a condition through the instruction that set the flags, as the AArch64
lift does (see [`crate::aarch64`]).

| File | What it is |
|---|---|
| `TI_MSP430.sla` | The 16-bit MSP430, little-endian: what `TI_MSP430:LE:16:default` — the loader's language for an `EM_MSP430` ELF — decodes under. |

The specification covers the whole instruction set: the single-operand rotates and shifts
(`RRC`, `RRA`, `SWPB`, `SXT`, `PUSH`), the two-operand arithmetic and logic (`MOV`, `ADD`,
`ADDC`, `SUB`, `SUBC`, `CMP`, `DADD`, `BIT`, `BIC`, `BIS`, `XOR`, `AND`), the jumps (`JNE`,
`JEQ`, `JNC`, `JC`, `JN`, `JGE`, `JL`, `JMP`) and the emulated instructions (`RET`, `POP`,
`CLR`, `TST`, `BR`, `NOP`, `ADC`, `RLC`, …). Unlike RISC-V's bit-manipulation extension, none
of it is left without p-code: every instruction the decoder reads, the lift can interpret.

The file is the one kuna's own command line unpacks from the specifications it carries (into
`~/.cache/kuna/specs-9e2d082eab3527da/Ghidra/Processors/TI_MSP430/data/languages/`), compiled
from the sources vendored in the kuna tree this workspace pins
(`specs/Ghidra/Processors/TI_MSP430/data/languages/TI_MSP430.slaspec`, with the `TI430Common.sinc`
it includes) by kuna's SLEIGH compiler at the same commit; the ARM, AArch64, MIPS and RISC-V
files here match that cache byte for byte. To compile it again:

```sh
# in the kuna checkout cargo keeps (~/.cargo/git/checkouts/kuna-*/<rev>/decompiler)
cargo build --release -p kuna-slacomp
target/release/slacomp ../specs/Ghidra/Processors/TI_MSP430/data/languages/TI_MSP430.slaspec
```

The specification is Ghidra's, under the Apache License, Version 2.0 (see `NOTICE` at the
root). Recompile it when the pinned kuna commit moves, so the runtime and the file agree.

The 20-bit MSP430X variant (`TI_MSP430X.sla`) is not carried: the toolchain here builds the
16-bit core, and an architecture is carried only with a fixture that exercises it.
