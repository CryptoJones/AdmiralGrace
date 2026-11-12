# The RISC-V specifications

Ghidra's SLEIGH specifications of RISC-V, compiled, carried inside the engine and read through
the SLEIGH runtime kuna ports, the way the ARM and MIPS specifications under `../arm` and
`../mips` are. RISC-V has no condition flags and no branch delay slot: a branch compares two
registers outright, and the instruction after it is its own. The compressed extension (C) makes
instructions two bytes as often as four, so the decoder steps a halfword at a time over what it
cannot read.

| File | What it is |
|---|---|
| `riscv32.sla` | 32-bit RISC-V, little-endian: what `RISCV:LE:32:…` — the loader's language for an `EM_RISCV` ELF of class ELF32 — decodes under. |
| `riscv64.sla` | The same, 64-bit: `RISCV:LE:64:…`. |

Both cover the base integer instruction set (I) and the standard extensions — multiply/divide
(M), atomics (A), single and double floating point (F, D) and compressed (C). The
bit-manipulation extension (B: `andn`, `clz`, `cpop`, `rev8`, the rotates, the shifted adds and
the rest) is decoded — its instructions disassemble — but Ghidra leaves its p-code
unimplemented, so a function that holds one is listed and not lifted. The decoder reads those
instructions through SLEIGH's assembly-only path, which renders the text without building
p-code.

Both are the files kuna's own command line unpacks from the specifications it carries (into
`~/.cache/kuna/specs-9e2d082eab3527da/Ghidra/Processors/RISCV/data/languages/`), compiled from the
sources vendored in the kuna tree this workspace pins (`specs/Ghidra/Processors/RISCV/data/languages/riscv.ilp32d.slaspec`
and `riscv.lp64d.slaspec`, with the `.sinc` files they include) by kuna's SLEIGH compiler at the
same commit; the ARM, AArch64 and MIPS files here match that cache byte for byte. To compile them
again:

```sh
# in the kuna checkout cargo keeps (~/.cargo/git/checkouts/kuna-*/<rev>/decompiler)
cargo build --release -p kuna-slacomp
target/release/slacomp ../specs/Ghidra/Processors/RISCV/data/languages/riscv.ilp32d.slaspec
target/release/slacomp ../specs/Ghidra/Processors/RISCV/data/languages/riscv.lp64d.slaspec
```

The specifications are Ghidra's, under the Apache License, Version 2.0 (see `NOTICE` at the
root). Recompile them when the pinned kuna commit moves, so the runtime and the files agree.
