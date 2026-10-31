# The ARM specifications

Ghidra's SLEIGH specifications of 32-bit ARM, compiled, carried inside the engine and read
through the SLEIGH runtime kuna ports (`kuna-sleigh`). One specification covers both the ARM
and the Thumb instruction sets; the `TMode` context bit says which one an address decodes in.

| File | What it is |
|---|---|
| `ARM7_le.sla` | ARMv7 and older, little-endian: what `ARM:LE:32:v7`, `ARM:LE:32:v6` and the Cortex-M profile decode under. |
| `ARM8_le.sla` | ARMv8's 32-bit state, little-endian: what `ARM:LE:32:v8` — the loader's answer for an image that names no older version — decodes under. |

Both were compiled from the sources vendored in the kuna tree this workspace pins
(`specs/Ghidra/Processors/ARM/data/languages/ARM7_le.slaspec` and `ARM8_le.slaspec`, with the
`.sinc` files they include), with kuna's SLEIGH compiler at the same commit:

```sh
# in the kuna checkout cargo keeps (~/.cargo/git/checkouts/kuna-*/<rev>/decompiler)
cargo build --release -p kuna-slacomp
target/release/slacomp ../specs/Ghidra/Processors/ARM/data/languages/ARM7_le.slaspec
target/release/slacomp ../specs/Ghidra/Processors/ARM/data/languages/ARM8_le.slaspec
```

The specifications are Ghidra's, under the Apache License, Version 2.0 (see `NOTICE` at the
root). Recompile them when the pinned kuna commit moves, so the runtime and the files agree.
