# Decision record: depend on kuna crates vs. growing the native decoder/loader

- **Issue:** [#6](https://github.com/CryptoJones/AdmiralGrace/issues/6)
- **Evaluated at:** kuna commit `28219c9` (Apache-2.0, `publish = false`)
- **Method:** fresh dependency measurement, all numbers below are from this machine (24 cores, 32 GB, release profile, warm external-registry cache; kuna git cache cold).

## Measured facts

| Metric | ag-ui baseline | ag-ui + kuna-base/num/sleigh/analysis |
|---|---|---|
| Cold `cargo build --release` | 5m 10s | 4m 48s |
| Peak compile RSS | 1.04 GB | 3.21 GB |
| Binary size | 23.80 MB | 25.68 MB (**+1.87 MB, +7.9%**) |

Integration build used kuna as **git dependencies pinned to the evaluated commit**. The built binary was exercised end-to-end (image loader path run against `/bin/ls` and our own `target/release/ag-ui`).

| Crate | Rust LOC | Notes |
|---|---|---|
| kuna-base | 15,073 | shared primitives |
| kuna-num | 4,551 | numeric stack |
| kuna-sleigh | 33,971 | SLEIGH runtime — reads compiled `.sla`; the `.slaspec` **source tree is vendored** (`specs/Ghidra/...`, x86-64 included), kuna-slacomp (~10k LOC) compiles them |
| kuna-analysis | 94,028 | loaders (ELF/PE/COFF/Mach-O incl. fat), PLT/GOT, DWARF, PDB, demangling, strings, function discovery, RTTI, **ObjC `__objc_classlist` pass** |
| kuna-decomp | 427,330 | the decompiler core (full Ghidra DECCORE port) |

### The kuna-analysis-without-kuna-decomp question

**Not currently separable.** `kuna-analysis/Cargo.toml` overrides with a real
`kuna-decomp.workspace = true` runtime dependency, and the code imports it
throughout: `architecture::Architecture`, `dtype::Datatype`,
`fspec::PrototypePieces`, `symbolnamechars`, `formatstring` modes live at
~20+ sites in `pass.rs`/`passes.rs`. There is no feature flag that cuts it.

## Trade-offs

**Native path (today: iced-x86 + `ag-corpus` overlays)**
- Small, fast builds (~1 min debug), zero giant dependencies, decode semantics already exercised by the corpus workflow.
- We own every correctness bug outright — and the review at `e9e6ced` proved the class exists: register identity collisions, mislabeled `+[Class sel]`, silent `imp → 0`, `drop_header` chopping function heads (#9–#14). The same bugs would re-grow in each new hand-written pass.

**kuna path**
- kuna-analysis replaces a whole class of hand-written loaders/pass work we have not built yet — not just fixing the found bugs: PLT/GOT, relocations, no-return detection, DWARF, ObjC naming come with provenance, while our corpus gives us none of these rails.
- Costs are real but modest on this box: cold release build time unchanged within noise (4m48s vs 5m10s), peak compile RSS up from 1.0 GB to 3.2 GB, +1.9 MB binary. SLEIGH semantics give Ghidra-parity decode replacing `iced-x86` byte-level views.
- Lifecycle: `publish = false` → git dep pinned to a commit or vendor. Either way the shipped binary redistributes Apache-2.0 code, so kuna's `NOTICE` (which carries Ghidra's) must ship with releases; vendoring additionally puts the text in-tree.
- SLEIGH first use requires compiling a `.sla` with kuna-slacomp (no precompiled artifacts are shipped).

## Recommendation (pending owner approval — not adopted yet)

Stage the adoption; keep the options reversible:

1. **Adopt now, as pinned git deps:** `kuna-analysis` (+ its chain) to power the data layer (issue #4/#5) and to replace `ag-corpus`'s hand-written ObjC/relocation/PLT overlays outright — deleting the code paths that contain issues #12/#13's damage and #14's dead code.
2. **Keep `iced-x86` in `ag-engine` short-term:** the CFG-walk bugs (#9/#10) are engine bugs regardless of decoder choice, and the workbench's native decode path stays tiny. Revisit SLEIGH when the engine moves toward p-code/ lifter parity (the decision point owning issue #10's flow semantics).
3. **Do not vendor:** git-dep pinning timestamps the semantics review of every bump; vendoring buys nothing today except NOTICE paperwork and 427k lines of immobile code in-tree.
4. **Revisit:** if the pinned-commit lifecycle becomes a bottleneck, split a minimal loader-only subset upstream (request, not fork).

Numbers to re-measure on CI/other hosts if developers notice a slower first build: cold release wall-clock, peak RSS, installed size (25.7 MB).
