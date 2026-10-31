# The AArch64 specification

Ghidra's SLEIGH specification of AArch64 — the 64-bit state of ARMv8 and after, little-endian
— compiled, carried inside the engine and read through the SLEIGH runtime kuna ports, the way
the ARM specifications under `../arm` are.

| File | What it is |
|---|---|
| `AARCH64.sla` | What 64-bit ARM decodes under: `AARCH64:LE:64:v8A`, the loader's language for an ELF or a PE, and `AARCH64:LE:64:AppleSilicon`, its language for a Mach-O. |

Compiled from the sources vendored in the kuna tree this workspace pins
(`specs/Ghidra/Processors/AARCH64/data/languages/AARCH64.slaspec` and the `.sinc` files it
includes), with kuna's SLEIGH compiler at the same commit:

```sh
# in the kuna checkout cargo keeps (~/.cargo/git/checkouts/kuna-*/<rev>/decompiler)
cargo build --release -p kuna-slacomp
target/release/slacomp ../specs/Ghidra/Processors/AARCH64/data/languages/AARCH64.slaspec
```

The specification is Ghidra's, under the Apache License, Version 2.0 (see `NOTICE` at the
root). Recompile it when the pinned kuna commit moves, so the runtime and the file agree.
