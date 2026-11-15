# The PowerPC specifications

Ghidra's SLEIGH specifications of PowerPC, compiled, carried inside the engine and read
through the SLEIGH runtime kuna ports, the way the ARM, MIPS and RISC-V specifications under
`../arm`, `../mips` and `../riscv` are. PowerPC has no branch delay slot: the instruction
after a branch is its own. The condition register a compare writes and a branch tests is
modelled as eight one-byte fields; the lift reads the comparisons back out of them.

| File | What it is |
|---|---|
| `ppc_32_be.sla` | 32-bit PowerPC, big-endian, with Altivec and the G2 core: what `PowerPC:BE:32:default` — the loader's language for an `EM_PPC` ELF whose `EI_DATA` says big-endian — decodes under. |
| `ppc_32_le.sla` | The same, little-endian: `PowerPC:LE:32:default`. |
| `ppc_64_be.sla` | 64-bit PowerPC, big-endian, with Altivec and G2: `PowerPC:BE:64:default`, the language for an `EM_PPC64` big-endian ELF. Its functions' symbols name ELFv1 descriptors in `.opd`; the loader reads the code address out of them. |
| `ppc_64_le.sla` | The same, little-endian: `PowerPC:LE:64:default`, the ELFv2 ABI. |
| `ppc_64_isa_vle_be.sla` | The Power ISA with VLE, big-endian, 64-bit registers over 32-bit addresses: `PowerPC:BE:64:VLE-32addr`. VLE's instructions are two bytes as often as four; the decoder sets the specification's `vle` context bit over the section so the 16-bit forms read. |

The paired-single extensions of the Gekko and Broadway cores (the GameCube and Wii) are not
in Ghidra's specifications; the decoder reads those instructions itself — primary opcode 4's
arithmetic and compares, and the quantized loads and stores of opcodes 56, 57, 60 and 61 —
before the specification, whose opcode 4 is Altivec's. `dcbz_l` shares `dcbz`'s encoding and
reads as `dcbz`.

All five are the files kuna's own command line unpacks from the specifications it carries
(into `~/.cache/kuna/specs-9e2d082eab3527da/Ghidra/Processors/PowerPC/data/languages/`),
compiled from the sources vendored in the kuna tree this workspace pins
(`specs/Ghidra/Processors/PowerPC/data/languages/ppc_32_be.slaspec` and its siblings, with
the `.sinc` files they include) by kuna's SLEIGH compiler at the same commit; the ARM,
AArch64, MIPS and RISC-V files here match that cache byte for byte, and these were verified
the same way. To compile them again:

```sh
# in the kuna checkout cargo keeps (~/.cargo/git/checkouts/kuna-*/<rev>/decompiler)
cargo build --release -p kuna-slacomp
target/release/slacomp ../specs/Ghidra/Processors/PowerPC/data/languages/ppc_32_be.slaspec
target/release/slacomp ../specs/Ghidra/Processors/PowerPC/data/languages/ppc_32_le.slaspec
target/release/slacomp ../specs/Ghidra/Processors/PowerPC/data/languages/ppc_64_be.slaspec
target/release/slacomp ../specs/Ghidra/Processors/PowerPC/data/languages/ppc_64_le.slaspec
target/release/slacomp ../specs/Ghidra/Processors/PowerPC/data/languages/ppc_64_isa_vle_be.slaspec
```

The specifications are Ghidra's, under the Apache License, Version 2.0 (see `NOTICE` at the
root). Recompile them when the pinned kuna commit moves, so the runtime and the files agree.
