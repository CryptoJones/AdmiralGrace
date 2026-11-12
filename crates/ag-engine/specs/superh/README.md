# The SuperH specification

Ghidra's SLEIGH specification of the Renesas SuperH SH4, compiled, carried inside the engine and
read through the SLEIGH runtime kuna ports, the way the ARM, MIPS, MSP430 and RISC-V
specifications under `../arm`, `../mips`, `../msp430` and `../riscv` are. SuperH is a 32-bit RISC
core: its sixteen general registers `r0`–`r15` are four bytes (`r15` the stack pointer), its
instructions are two bytes, and its condition flag is the `T` bit of the status register `SR` —
a compare (`cmp/eq`, `cmp/gt`, …) or a test (`tst`) sets it, and a conditional branch (`bt`,
`bf`) reads it. Like MIPS, SuperH has a branch delay slot: the instruction after a branch runs
before the branch takes effect, so the decoder folds the slot's p-code into the branch and marks
it (see [`crate::superh`], [`crate::mips`]).

| File | What it is |
|---|---|
| `SuperH4_le.sla` | The SH4, little-endian: what `SuperH4:LE:32:default` — the language the engine names for an `EM_SH` ELF (machine word `42`) of little-endian class — decodes under. |

The specification covers the SH4 instruction set: the loads and stores (`mov`, `mov.b`,
`mov.w`, `mov.l`, the indexed and pre/post-decrement forms), the arithmetic and logic (`add`,
`sub`, `and`, `or`, `xor`, `not`, `neg`, `negc`, `addc`, `subc`, the immediate forms), the
shifts and rotates (`shll`, `shlr`, `shal`, `shar`, `shll2`, `shlr8`, `rotl`, `rotr`, `rotcl`,
`rotcr`), the compares and tests (`cmp/eq`, `cmp/hs`, `cmp/ge`, `cmp/hi`, `cmp/gt`, `cmp/pl`,
`cmp/pz`, `cmp/str`, `tst`), the branches and calls (`bt`, `bf`, `bt/s`, `bf/s`, `bra`, `bsr`,
`jmp`, `jsr`, `rts`, `rte`), the multiply and multiply-accumulate (`mul.l`, `dmuls`, `dmulu`,
`mac`, `macs`), the system and control instructions (`lds`, `sts`, `ldc`, `stc`, `trapa`,
`sleep`, `pref`, `movca`, `ocbi`, `ocbp`, `ocbwb`) and the floating-point operations. The engine
decodes it but does not lift it to pseudocode: the listing and the graph are what it opens, as
ARM and MIPS are.

The file is the one kuna's own command line unpacks from the specifications it carries (into
`~/.cache/kuna/specs-9e2d082eab3527da/Ghidra/Processors/SuperH4/data/languages/`), compiled from
the source vendored in the kuna tree this workspace pins
(`specs/Ghidra/Processors/SuperH4/data/languages/SuperH4_le.slaspec`, with the `SuperH4.sinc` it
includes) by kuna's SLEIGH compiler at the same commit; it matches that cache byte for byte. To
compile it again:

```sh
# in the kuna checkout cargo keeps (~/.cargo/git/checkouts/kuna-*/<rev>/decompiler)
cargo build --release -p kuna-slacomp
target/release/slacomp ../specs/Ghidra/Processors/SuperH4/data/languages/SuperH4_le.slaspec
```

The specification is Ghidra's, under the Apache License, Version 2.0 (see `NOTICE` at the
root). Recompile it when the pinned kuna commit moves, so the runtime and the file agree.

The big-endian twin (`SuperH4_be.sla`) is not carried: the SH4 toolchain here links
little-endian only, and an architecture is carried only with a fixture that exercises it. The
earlier SH-1, SH-2 and SH-2A cores (`sh-1.sla`, `sh-2.sla`, `sh-2a.sla` under the `SuperH`
processor) are separate specifications this engine does not carry; the fixture here is the SH4.
