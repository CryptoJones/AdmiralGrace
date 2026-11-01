# The MIPS specifications

Ghidra's SLEIGH specifications of 32-bit MIPS, compiled, carried inside the engine and read
through the SLEIGH runtime kuna ports, the way the ARM specifications under `../arm` are. SLEIGH
models MIPS's branch delay slots: a branch's p-code holds its slot's, and the decoder reads the
two apart.

| File | What it is |
|---|---|
| `mips32le.sla` | 32-bit MIPS, little-endian: what `MIPS:LE:32:default` — the loader's language for an `EM_MIPS` ELF whose `EI_DATA` says little-endian — decodes under. |
| `mips32be.sla` | The same, big-endian: `MIPS:BE:32:default`. |

Both are the files kuna's own command line unpacks from the specifications it carries (into
`~/.cache/kuna/specs-9e2d082eab3527da/Ghidra/Processors/MIPS/data/languages/`), compiled from the
sources vendored in the kuna tree this workspace pins (`specs/Ghidra/Processors/MIPS/data/languages/mips32le.slaspec`
and `mips32be.slaspec`, with the `.sinc` files they include) by kuna's SLEIGH compiler at the same
commit; the ARM and AArch64 files here match that cache byte for byte. To compile them again:

```sh
# in the kuna checkout cargo keeps (~/.cargo/git/checkouts/kuna-*/<rev>/decompiler)
cargo build --release -p kuna-slacomp
target/release/slacomp ../specs/Ghidra/Processors/MIPS/data/languages/mips32le.slaspec
target/release/slacomp ../specs/Ghidra/Processors/MIPS/data/languages/mips32be.slaspec
```

The specifications are Ghidra's, under the Apache License, Version 2.0 (see `NOTICE` at the
root). Recompile them when the pinned kuna commit moves, so the runtime and the files agree.
