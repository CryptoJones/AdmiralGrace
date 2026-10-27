# AdmiralGrace backlog

One list, two views: this file and the [GitHub Issues tab](https://github.com/CryptoJones/AdmiralGrace/issues) are kept in sync. Every open item here has an issue and every open issue has a line here; adding an item means filing the issue and linking it, closing an issue means checking the box.

Seeded 2026-10-23 from two sources: the code review of the engine foundation at `e9e6ced` (PR #1), and the review of [kuna](https://github.com/Noelo-Lab/kuna), the agent-first Rust port of the Ghidra decompiler. Review items are grouped; each group is one issue, and the issue carries the full repro list.

## P0 — Engine correctness (`ag-engine`)

### CFG builder (done) — [#9](https://github.com/CryptoJones/AdmiralGrace/issues/9)
- [x] No block splitting → **overlapping blocks**: `74 02 90 90 c3` @0x1000 (if-diamond) yields blocks `[0x1000,0x1002)` and `[0x1002,0x1005)` overlapping tail block `[0x1004,0x1005)`; backward `jne` into mid-block (`31 c0 ff c0 83 f8 0a 75 f9 c3`) overlaps the entry block. `resolve_branches` (`cfgwalk.rs` ~23–97) never checks whether the next address starts/extends an existing block.
- [x] Dangling successor: `eb 00 c3` → block `[0x1000,0x1002)` lists successor `0x1002` but that block start is never scheduled.
- [x] Indirect calls lose the graph: `ff d0 c3` → 1 block, no successor, `call_sites` empty; the continuation is unreachable in the CFG (catch-all arm, `cfgwalk.rs` ~87–90).
- [x] Called targets walked into the caller's `ProcedureCfg`: `e8 …` pushes the callee onto the same frontier — callee blocks end up inside the caller; targets belong in `call_sites` only.
- [x] Duplicate successors not filtered within a block (loop case lists target + fallthrough twice).

### Decoder instruction flow (done) — [#10](https://github.com/CryptoJones/AdmiralGrace/issues/10)
- [x] `ud2` / `xbegin` abort the **whole segment** decode (`FlowControl::Exception → bail!`). Real x86-64 functions carry `ud2` constantly. Expected: decode the instruction, record a trap marker, continue. Pinned test: `0f 0b c3` currently → `Err`.
- [x] `syscall` decodes to `Flow::Call(0)` — misleading semantics.
- [x] `Flow::Xbegin` declared but never constructed (dead variant).

### Register identity (done) — [#11](https://github.com/CryptoJones/AdmiralGrace/issues/11)
- [x] 8-bit GPR numbering collision: `AH` → index 4, same as `SP`/`RSP` → AH ≡ RSP in `Operands`.
- [x] Non-GPR/XMM registers forced to index 0: every `ymm`/`zmm`/k-register collapses to the same `RegisterId`.
- [x] Operand width dropped: `89 c0` and `48 89 c0` produce identical `Operands`.
- [x] `RegisterSet` `1u64 << (index & 63)`: silently **aliases** any index ≥ 64 into 0 (latent until identity is fixed).

## P0 — CLI (`ag-cli`) (done) — [#12](https://github.com/CryptoJones/AdmiralGrace/issues/12)
- [x] Byte-boundary panics: `&types[..60]` and `name.truncate(70)` panic on multi-byte characters at the cut point (valid non-ASCII names/type encodings). Needs char-safe truncation.
- [x] `0X1000` accepted by the resolve prefix check but rejected by `parse_addr` (only lowercase `0x` is stripped) → whole subcommand errors out.

## P0 — Silent data damage (`ag-corpus`) (done) — [#13](https://github.com/CryptoJones/AdmiralGrace/issues/13)
- [x] Unparseable IMP silently becomes `imp_addr 0` (`unwrap_or(0)`); hex parse also strips only lowercase `0x`.
- [x] Class methods `+[Class sel]` rendered/stored as `-[Class sel]`; `by_name` uses that key, so collisions resolve last-write-wins via `insert`.
- [x] Double `with_shift` desyncs `by_imp` (keys accumulate) vs `imp_addr` (current shift only); `by_name` is never re-shifted.
- [x] `drop_header` cuts the function head at the first blank line (`"// hdr\nint f(void) {\n  int a;\n\n  return a;\n}"` → `"  return a;\n}"`); single-line headers stay glued in.
- [x] `to_function` errors silently skipped; duplicate addresses silently keep the first entry.
- [x] `parse_addr` rejects uppercase `0X` prefix. — fixed in #37
- [x] `Sha256` field is dead storage (never read).

## Hygiene (done) — [#14](https://github.com/CryptoJones/AdmiralGrace/issues/14)
- [x] `LICENSE` file missing (Cargo.toml declares MIT).
- [x] Unused dependencies: `walkdir` (workspace), `serde`/`serde_json` (`ag-engine`, `ag-cli`), `regex` (`ag-corpus`).
- [x] Dead variant: `Flow::Xbegin` (see decoder flow) — tracked in #10.

## kuna-derived work

### data layer and workbench

- [x] Graph tab: draw the control-flow graph of the selected function for a program image — [#49](https://github.com/CryptoJones/AdmiralGrace/issues/49)
- [x] Graph tab: route an edge that skips a rank around the blocks in between, and keep the edge labels apart — [#59](https://github.com/CryptoJones/AdmiralGrace/issues/59)
- [x] ag image: cfg and calls subcommands, so the CLI reports what the Graph and References tabs show — [#62](https://github.com/CryptoJones/AdmiralGrace/issues/62)
- [x] README screenshots: add the bytes pane, the strings tab and the graph tab of a program image — [#63](https://github.com/CryptoJones/AdmiralGrace/issues/63)
- [x] One rule for fall-through and taken edges: the Graph tab takes its edges from ag-image — [#67](https://github.com/CryptoJones/AdmiralGrace/issues/67)
- [x] References tab for a program image: data references, from the instructions that point at named data — [#70](https://github.com/CryptoJones/AdmiralGrace/issues/70)
- [x] Fixtures and tests for a PE and a Mach-O image — [#71](https://github.com/CryptoJones/AdmiralGrace/issues/71)
- [x] Decode 32-bit x86: take the bitness from the image's language — [#76](https://github.com/CryptoJones/AdmiralGrace/issues/76)
- [x] Lifter, first milestone: pseudocode for straight-line x86-64 functions — [#77](https://github.com/CryptoJones/AdmiralGrace/issues/77)
- [x] Lifter, second milestone: straight-line functions that call, by lifting the fall-through chain of blocks — [#83](https://github.com/CryptoJones/AdmiralGrace/issues/83)
- [x] Lifter, third milestone: structured control flow (if/else, loops) — [#88](https://github.com/CryptoJones/AdmiralGrace/issues/88)
- [x] Lifter: tail jumps and thunks (PLT stubs, tail calls) — [#91](https://github.com/CryptoJones/AdmiralGrace/issues/91)
- [x] Lifter: a comparison of two computed addresses prints as rax != rax — [#97](https://github.com/CryptoJones/AdmiralGrace/issues/97)
- [x] CFG walk: stop at a jmp to another function's entry (tail-call edge) — [#98](https://github.com/CryptoJones/AdmiralGrace/issues/98)
- [x] CFG walk: hlt does not fall through — [#104](https://github.com/CryptoJones/AdmiralGrace/issues/104)
- [x] Lifter: return-value liveness from the callers — [#92](https://github.com/CryptoJones/AdmiralGrace/issues/92)
- [x] ag image export: the whole analysis of an image as a directory of JSON and text — [#78](https://github.com/CryptoJones/AdmiralGrace/issues/78)
- [x] Bytes pane for a program image: show the bytes around the selection — [#50](https://github.com/CryptoJones/AdmiralGrace/issues/50)
- [x] Strings for a program image: scan the data sections and link each string to the code that uses it — [#51](https://github.com/CryptoJones/AdmiralGrace/issues/51)
- [x] Open a raw binary in the workbench through ag-engine::Image — [#42](https://github.com/CryptoJones/AdmiralGrace/issues/42)

- [x] Add a kuna project-export provider (index.jsonl + .c/.h/.asm) to ag-corpus and ag-ui — [#4](https://github.com/CryptoJones/AdmiralGrace/issues/4)
- [x] Use kuna's JSON surfaces to fill the navigator, inspector and graph panes — [#5](https://github.com/CryptoJones/AdmiralGrace/issues/5)

### engine

- [x] Evaluate depending on kuna-sleigh and kuna-analysis instead of a hand-written decoder and loader — [#6](https://github.com/CryptoJones/AdmiralGrace/issues/6)
- [x] Option registry with a generated catalog and symptom index for engine decisions — [#8](https://github.com/CryptoJones/AdmiralGrace/issues/8)

### cli

- [x] `ag image`: inspect a binary from the CLI through ag-engine::Image — [#43](https://github.com/CryptoJones/AdmiralGrace/issues/43)

- [x] `ag install-skill` and `ag docs`: ship an agent skill and the manual inside the binary — [#7](https://github.com/CryptoJones/AdmiralGrace/issues/7)

## Hopper parity

Filed 2026-10-26 from a comparison with Hopper Disassembler's public documentation: the hopperapp.com tutorial, the Linux build's `--help`, its MCP tool list and its published Python API reference.

### Annotation and persistence

- [ ] Project file: save the analysis and the analyst's annotations in a portable format — [#113](https://github.com/CryptoJones/AdmiralGrace/issues/113)
- [ ] Rename functions, labels and local variables, in the CLI and the workbench — [#114](https://github.com/CryptoJones/AdmiralGrace/issues/114)
- [ ] Rename a register within one function's pseudocode — [#115](https://github.com/CryptoJones/AdmiralGrace/issues/115)
- [ ] Comments: line and inline comments at an address — [#116](https://github.com/CryptoJones/AdmiralGrace/issues/116)
- [ ] Bookmarks: named places of interest, listed and navigable — [#117](https://github.com/CryptoJones/AdmiralGrace/issues/117)
- [ ] Tags on addresses, blocks and functions, with filtering by tag — [#118](https://github.com/CryptoJones/AdmiralGrace/issues/118)
- [ ] Colors on addresses, blocks and functions — [#119](https://github.com/CryptoJones/AdmiralGrace/issues/119)
- [ ] Undo and redo for every analyst change — [#120](https://github.com/CryptoJones/AdmiralGrace/issues/120)
- [ ] Manually add and remove cross references — [#121](https://github.com/CryptoJones/AdmiralGrace/issues/121)

### Correcting the analysis

- [ ] Mark bytes as code, function, data, string or undefined — [#122](https://github.com/CryptoJones/AdmiralGrace/issues/122)
- [ ] Operand display format: hex, signed, decimal, octal, or as an address — [#123](https://github.com/CryptoJones/AdmiralGrace/issues/123)
- [ ] Switch tables: recover jump tables, with a manual hint when recovery fails — [#124](https://github.com/CryptoJones/AdmiralGrace/issues/124)
- [ ] Analysis options: branches end procedures, and code sections hold only procedures — [#125](https://github.com/CryptoJones/AdmiralGrace/issues/125)

### Modifying the binary

- [ ] Assembler: assemble an instruction in place — [#126](https://github.com/CryptoJones/AdmiralGrace/issues/126)
- [ ] NOP a region — [#127](https://github.com/CryptoJones/AdmiralGrace/issues/127)
- [ ] Editable Bytes pane — [#128](https://github.com/CryptoJones/AdmiralGrace/issues/128)
- [ ] Write a patched executable — [#129](https://github.com/CryptoJones/AdmiralGrace/issues/129)
- [ ] Rebase the image, and create, delete and rename segments — [#130](https://github.com/CryptoJones/AdmiralGrace/issues/130)

### Architectures and formats

- [ ] Decode 32-bit ARM and Thumb, with per-address mode switching — [#131](https://github.com/CryptoJones/AdmiralGrace/issues/131)
- [ ] Decode and lift AArch64 — [#132](https://github.com/CryptoJones/AdmiralGrace/issues/132)
- [ ] Load a raw binary with a base address, entry point, file offset and length — [#133](https://github.com/CryptoJones/AdmiralGrace/issues/133)
- [ ] Universal (FAT) Mach-O: list the slices and pick one — [#134](https://github.com/CryptoJones/AdmiralGrace/issues/134)

### Metadata recovery

- [ ] Read Objective-C metadata from the binary — [#135](https://github.com/CryptoJones/AdmiralGrace/issues/135)
- [ ] Generate an Objective-C header from a binary — [#136](https://github.com/CryptoJones/AdmiralGrace/issues/136)
- [ ] Read Swift metadata and demangle Swift names — [#137](https://github.com/CryptoJones/AdmiralGrace/issues/137)
- [ ] Demangle C++ names — [#138](https://github.com/CryptoJones/AdmiralGrace/issues/138)
- [ ] Find functions from exception and unwind data — [#139](https://github.com/CryptoJones/AdmiralGrace/issues/139)

### Decompiler and views

- [ ] Pseudocode: print Objective-C message sends as [receiver selector] — [#140](https://github.com/CryptoJones/AdmiralGrace/issues/140)
- [ ] Pseudocode: a toggle to show or hide dead code — [#141](https://github.com/CryptoJones/AdmiralGrace/issues/141)
- [ ] Graph tab: minimap, block grouping, block colors, editable block text, keyboard navigation — [#142](https://github.com/CryptoJones/AdmiralGrace/issues/142)
- [ ] Graph tab: export the graph as PDF and SVG — [#143](https://github.com/CryptoJones/AdmiralGrace/issues/143)
- [ ] Listing: jump arrows in the margin — [#144](https://github.com/CryptoJones/AdmiralGrace/issues/144)

### Automation

- [ ] MCP server over the ag data layer — [#145](https://github.com/CryptoJones/AdmiralGrace/issues/145)
- [ ] Scripting API with headless script execution — [#146](https://github.com/CryptoJones/AdmiralGrace/issues/146)
- [ ] Plugin SDK for loaders, architectures and tools — [#147](https://github.com/CryptoJones/AdmiralGrace/issues/147)

### Dynamic analysis

- [ ] Debugger frontend for LLDB and GDB — [#148](https://github.com/CryptoJones/AdmiralGrace/issues/148)

## Binary Ninja parity

Filed 2026-10-26: features Binary Ninja documents publicly (docs.binary.ninja, its release posts and the Vector35 GitHub repos) that neither AdmiralGrace nor Hopper has. Each issue links its source.

### Intermediate languages

- [ ] Expose a multi-level IL (low, medium, high) with SSA forms to the API — [#149](https://github.com/CryptoJones/AdmiralGrace/issues/149)
- [ ] Workbench: switch any pane between disassembly and each IL level — [#150](https://github.com/CryptoJones/AdmiralGrace/issues/150)
- [ ] IL render options: opcodes, flag use, stack pointer value, expression types, casts — [#151](https://github.com/CryptoJones/AdmiralGrace/issues/151)
- [ ] IL rewriting API for plugins — [#152](https://github.com/CryptoJones/AdmiralGrace/issues/152)
- [ ] Function-level, context-aware lifting for complex ISAs — [#153](https://github.com/CryptoJones/AdmiralGrace/issues/153)
- [ ] Model architecture flags with producer and consumer semantics — [#154](https://github.com/CryptoJones/AdmiralGrace/issues/154)
- [ ] IL emulator — [#155](https://github.com/CryptoJones/AdmiralGrace/issues/155)
- [ ] IL-to-C++ transpiler for testing lifters — [#156](https://github.com/CryptoJones/AdmiralGrace/issues/156)

### Decompiler output and control

- [ ] Pluggable output languages: Pseudo-C, Pseudo-Rust, Pseudo-ObjC, Pseudo-Python — [#157](https://github.com/CryptoJones/AdmiralGrace/issues/157)
- [ ] Per-site decompiler overrides: early return, expression folding, condition inversion, switch recovery — [#158](https://github.com/CryptoJones/AdmiralGrace/issues/158)
- [ ] Per-variable dead store elimination — [#159](https://github.com/CryptoJones/AdmiralGrace/issues/159)
- [ ] Pseudocode formatting options: brace style, rainbow braces, indent guides, ternaries, wrapping, call parameter hints — [#160](https://github.com/CryptoJones/AdmiralGrace/issues/160)
- [ ] Outline inlined memcpy, memset and strcpy into builtins — [#161](https://github.com/CryptoJones/AdmiralGrace/issues/161)
- [ ] Struct initializer expressions in pseudocode — [#162](https://github.com/CryptoJones/AdmiralGrace/issues/162)
- [ ] Translate Windows CFG dispatch calls and jumps to functions into direct calls and tail calls — [#163](https://github.com/CryptoJones/AdmiralGrace/issues/163)
- [ ] Detect conditionally non-returning functions — [#164](https://github.com/CryptoJones/AdmiralGrace/issues/164)
- [ ] Guided analysis: choose per block which branch targets to analyze — [#165](https://github.com/CryptoJones/AdmiralGrace/issues/165)
- [ ] Inline a function during analysis — [#166](https://github.com/CryptoJones/AdmiralGrace/issues/166)
- [ ] Opaque predicate patcher — [#167](https://github.com/CryptoJones/AdmiralGrace/issues/167)
- [ ] Program slicing views — [#168](https://github.com/CryptoJones/AdmiralGrace/issues/168)

### Variables and data flow

- [ ] Merge and split variables — [#169](https://github.com/CryptoJones/AdmiralGrace/issues/169)
- [ ] Force a new variable version for per-path naming and typing — [#170](https://github.com/CryptoJones/AdmiralGrace/issues/170)
- [ ] User-informed data flow: set a variable's value or range — [#171](https://github.com/CryptoJones/AdmiralGrace/issues/171)
- [ ] Expose possible-value-set analysis in the workbench and the CLI — [#172](https://github.com/CryptoJones/AdmiralGrace/issues/172)
- [ ] Variables pane: register, stack and flag variables with their placement — [#173](https://github.com/CryptoJones/AdmiralGrace/issues/173)
- [ ] Stack layout pane with variable creation — [#174](https://github.com/CryptoJones/AdmiralGrace/issues/174)
- [ ] Listing: stack-offset column — [#175](https://github.com/CryptoJones/AdmiralGrace/issues/175)
- [ ] Highlight every instruction that reads or writes the selected register's value — [#176](https://github.com/CryptoJones/AdmiralGrace/issues/176)
- [ ] Track and override global pointer registers — [#177](https://github.com/CryptoJones/AdmiralGrace/issues/177)
- [ ] Type fragments: track parts of a struct held in registers — [#178](https://github.com/CryptoJones/AdmiralGrace/issues/178)

### Type system

- [ ] Type system: structs, unions, enums and typedefs, with a C type parser and a Types view — [#179](https://github.com/CryptoJones/AdmiralGrace/issues/179)
- [ ] Smart structures: build a struct from the accesses to a pointer — [#180](https://github.com/CryptoJones/AdmiralGrace/issues/180)
- [ ] Type propagation with automatic array and struct detection — [#181](https://github.com/CryptoJones/AdmiralGrace/issues/181)
- [ ] Choose the union field per instruction — [#182](https://github.com/CryptoJones/AdmiralGrace/issues/182)
- [ ] Bitfield struct members — [#183](https://github.com/CryptoJones/AdmiralGrace/issues/183)
- [ ] Type attributes: packing, base classes, noreturn, pure, custom value locations and more — [#184](https://github.com/CryptoJones/AdmiralGrace/issues/184)
- [ ] Model C++ classes, inheritance and virtual function tables — [#185](https://github.com/CryptoJones/AdmiralGrace/issues/185)
- [ ] Parse MSVC and Itanium RTTI and build vtable structures — [#186](https://github.com/CryptoJones/AdmiralGrace/issues/186)
- [ ] Type libraries: per-library types and signatures, applied by import name — [#187](https://github.com/CryptoJones/AdmiralGrace/issues/187)
- [ ] Type archives shared across projects — [#188](https://github.com/CryptoJones/AdmiralGrace/issues/188)
- [ ] Platform types per OS and architecture, editable by the user — [#189](https://github.com/CryptoJones/AdmiralGrace/issues/189)
- [ ] Import types from C headers with compiler flags — [#190](https://github.com/CryptoJones/AdmiralGrace/issues/190)
- [ ] Export types as a C header — [#191](https://github.com/CryptoJones/AdmiralGrace/issues/191)
- [ ] Port types and signatures from another project by matching symbols — [#192](https://github.com/CryptoJones/AdmiralGrace/issues/192)
- [ ] Import COM interface types by GUID — [#193](https://github.com/CryptoJones/AdmiralGrace/issues/193)
- [ ] Apply JNI types to Java_* and JNI_* functions automatically — [#194](https://github.com/CryptoJones/AdmiralGrace/issues/194)
- [ ] Cross references for types and struct members — [#195](https://github.com/CryptoJones/AdmiralGrace/issues/195)
- [ ] Show a constant as an enum member — [#196](https://github.com/CryptoJones/AdmiralGrace/issues/196)
- [ ] Quick data-typing keys: width, sign, complement, char array, pointer, array — [#197](https://github.com/CryptoJones/AdmiralGrace/issues/197)

### Function signatures

- [ ] Edit function properties: prototype, calling convention, stack adjustment, clobbers, value locations — [#198](https://github.com/CryptoJones/AdmiralGrace/issues/198)
- [ ] Support more calling conventions, including Go, Pascal and struct-by-value — [#199](https://github.com/CryptoJones/AdmiralGrace/issues/199)
- [ ] Per-function analysis settings — [#200](https://github.com/CryptoJones/AdmiralGrace/issues/200)

### Strings and constants

- [ ] Strings: UTF-32, big-endian wide strings and code pages — [#201](https://github.com/CryptoJones/AdmiralGrace/issues/201)
- [ ] String recognizer API for decoding obfuscated strings — [#202](https://github.com/CryptoJones/AdmiralGrace/issues/202)
- [ ] Constant renderer API — [#203](https://github.com/CryptoJones/AdmiralGrace/issues/203)
- [ ] Strings that are not NUL-terminated (Go) — [#204](https://github.com/CryptoJones/AdmiralGrace/issues/204)

### Library identification

- [ ] Function matching by whole-function hash that applies names, types and comments — [#205](https://github.com/CryptoJones/AdmiralGrace/issues/205)
- [ ] Networked signature server — [#206](https://github.com/CryptoJones/AdmiralGrace/issues/206)
- [ ] Highlight matched library functions and choose between matches — [#207](https://github.com/CryptoJones/AdmiralGrace/issues/207)
- [ ] Byte-pattern signature libraries — [#208](https://github.com/CryptoJones/AdmiralGrace/issues/208)

### Diffing

- [ ] Binary similarity and diffing between versions — [#209](https://github.com/CryptoJones/AdmiralGrace/issues/209)
- [ ] Export BinExport for BinDiff — [#210](https://github.com/CryptoJones/AdmiralGrace/issues/210)

### Debug info and interop

- [ ] Import PDB debug info, with symbol server download — [#211](https://github.com/CryptoJones/AdmiralGrace/issues/211)
- [ ] Import DWARF from the image, a sibling file, a dSYM, debuginfod or a build-ID directory — [#212](https://github.com/CryptoJones/AdmiralGrace/issues/212)
- [ ] Export the analysis as DWARF — [#213](https://github.com/CryptoJones/AdmiralGrace/issues/213)
- [ ] Import IDA databases and type libraries — [#214](https://github.com/CryptoJones/AdmiralGrace/issues/214)
- [ ] Import Ghidra databases and projects — [#215](https://github.com/CryptoJones/AdmiralGrace/issues/215)
- [ ] Export to a Ghidra .gzf — [#216](https://github.com/CryptoJones/AdmiralGrace/issues/216)
- [ ] Import CMSIS SVD peripheral maps — [#217](https://github.com/CryptoJones/AdmiralGrace/issues/217)
- [ ] Load an external debug info file, through a pluggable debug info parser API — [#218](https://github.com/CryptoJones/AdmiralGrace/issues/218)

### Architectures

- [ ] Decode and lift MIPS, including nanoMIPS — [#219](https://github.com/CryptoJones/AdmiralGrace/issues/219)
- [ ] Decode and lift PowerPC, including VLE — [#220](https://github.com/CryptoJones/AdmiralGrace/issues/220)
- [ ] Decode and lift RISC-V — [#221](https://github.com/CryptoJones/AdmiralGrace/issues/221)
- [ ] Decode and lift MSP430 — [#222](https://github.com/CryptoJones/AdmiralGrace/issues/222)
- [ ] Decode TriCore, Hexagon, TMS320C6x, C-SKY and NDS32 — [#223](https://github.com/CryptoJones/AdmiralGrace/issues/223)
- [ ] Decode 6502, Z80 and SuperH — [#224](https://github.com/CryptoJones/AdmiralGrace/issues/224)
- [ ] x86 extras: AT&T syntax, APX, MPX and the x32 ABI — [#225](https://github.com/CryptoJones/AdmiralGrace/issues/225)
- [ ] Architecture hook API: patch an architecture's lifting from a plugin — [#226](https://github.com/CryptoJones/AdmiralGrace/issues/226)

### Formats and loaders

- [ ] Load the dyld shared cache, one image at a time — [#227](https://github.com/CryptoJones/AdmiralGrace/issues/227)
- [ ] Load an Apple kernelcache — [#228](https://github.com/CryptoJones/AdmiralGrace/issues/228)
- [ ] Load MediaTek MD1ROM modem images — [#229](https://github.com/CryptoJones/AdmiralGrace/issues/229)
- [ ] Load VxWorks images and TI COFF — [#230](https://github.com/CryptoJones/AdmiralGrace/issues/230)
- [ ] Load minidumps and core dumps — [#231](https://github.com/CryptoJones/AdmiralGrace/issues/231)
- [ ] Load Intel HEX, Motorola S-record and TI-TXT — [#232](https://github.com/CryptoJones/AdmiralGrace/issues/232)
- [ ] UEFI and TE images, with EFI protocol resolution — [#233](https://github.com/CryptoJones/AdmiralGrace/issues/233)
- [ ] More platforms: FreeBSD, Windows kernel, macOS kernel, EFI, DECREE — [#234](https://github.com/CryptoJones/AdmiralGrace/issues/234)
- [ ] Detect the base address of raw firmware — [#235](https://github.com/CryptoJones/AdmiralGrace/issues/235)
- [ ] Memory map editing: file-backed, pattern and unbacked regions, section semantics — [#236](https://github.com/CryptoJones/AdmiralGrace/issues/236)
- [ ] Load options per loader, remembered per file — [#237](https://github.com/CryptoJones/AdmiralGrace/issues/237)
- [ ] Kaitai Struct parsing in a structure tree — [#238](https://github.com/CryptoJones/AdmiralGrace/issues/238)

### Containers and transforms

- [ ] Open files inside archives and containers — [#239](https://github.com/CryptoJones/AdmiralGrace/issues/239)
- [ ] Byte transforms: Base64, hex, XOR, compression, and copy-as and paste-from — [#240](https://github.com/CryptoJones/AdmiralGrace/issues/240)
- [ ] Extract embedded blobs from firmware — [#241](https://github.com/CryptoJones/AdmiralGrace/issues/241)

### Patching

- [ ] Compile C source into a patch — [#242](https://github.com/CryptoJones/AdmiralGrace/issues/242)
- [ ] Preset branch patches: invert, always branch, never branch, skip and return a value — [#243](https://github.com/CryptoJones/AdmiralGrace/issues/243)
- [ ] Create a memory region when a patch writes to unbacked addresses — [#244](https://github.com/CryptoJones/AdmiralGrace/issues/244)

### Analysis pipeline and automation

- [ ] Workflows: customizable analysis pipelines — [#245](https://github.com/CryptoJones/AdmiralGrace/issues/245)
- [ ] Analysis modes and limits — [#246](https://github.com/CryptoJones/AdmiralGrace/issues/246)
- [ ] Find functions by linear sweep and pointer sweep — [#247](https://github.com/CryptoJones/AdmiralGrace/issues/247)
- [ ] Open at main rather than the entry point — [#248](https://github.com/CryptoJones/AdmiralGrace/issues/248)
- [ ] Settings with user, project and resource scopes — [#249](https://github.com/CryptoJones/AdmiralGrace/issues/249)
- [ ] C API and bindings for other languages — [#250](https://github.com/CryptoJones/AdmiralGrace/issues/250)
- [ ] Render layer API — [#251](https://github.com/CryptoJones/AdmiralGrace/issues/251)
- [ ] Data renderer API — [#252](https://github.com/CryptoJones/AdmiralGrace/issues/252)
- [ ] Custom flow graph and graph layout API — [#253](https://github.com/CryptoJones/AdmiralGrace/issues/253)
- [ ] Plugin UI API: forms and background tasks — [#254](https://github.com/CryptoJones/AdmiralGrace/issues/254)
- [ ] Pluggable providers for scripting, secrets and downloads — [#255](https://github.com/CryptoJones/AdmiralGrace/issues/255)
- [ ] Store arbitrary metadata in the project, per function and globally — [#256](https://github.com/CryptoJones/AdmiralGrace/issues/256)
- [ ] Let plugins add MCP tools — [#257](https://github.com/CryptoJones/AdmiralGrace/issues/257)

### Workbench

- [ ] Triage summary view — [#258](https://github.com/CryptoJones/AdmiralGrace/issues/258)
- [ ] Feature map: a colored overview of the whole binary — [#259](https://github.com/CryptoJones/AdmiralGrace/issues/259)
- [ ] Byte overview view in CP437 — [#260](https://github.com/CryptoJones/AdmiralGrace/issues/260)
- [ ] Command palette — [#261](https://github.com/CryptoJones/AdmiralGrace/issues/261)
- [ ] Custom key bindings, with IDA and Ghidra presets — [#262](https://github.com/CryptoJones/AdmiralGrace/issues/262)
- [ ] Themes and a color-blind mode — [#263](https://github.com/CryptoJones/AdmiralGrace/issues/263)
- [ ] Tiled, synced and locked panes — [#264](https://github.com/CryptoJones/AdmiralGrace/issues/264)
- [ ] History pane: revert to any earlier annotation state — [#265](https://github.com/CryptoJones/AdmiralGrace/issues/265)
- [ ] Folders in the symbols list — [#266](https://github.com/CryptoJones/AdmiralGrace/issues/266)
- [ ] Cross references pane: tree and table layouts, filters, pinning — [#267](https://github.com/CryptoJones/AdmiralGrace/issues/267)
- [ ] Advanced search: wildcard byte patterns, YARA hex, regex, constants, text in pseudocode — [#268](https://github.com/CryptoJones/AdmiralGrace/issues/268)
- [ ] Hover previews of a reference's target — [#269](https://github.com/CryptoJones/AdmiralGrace/issues/269)
- [ ] URL handler: deep links to an address, and copy location as URL — [#270](https://github.com/CryptoJones/AdmiralGrace/issues/270)
- [ ] Analysis log: filter by view and by logger — [#271](https://github.com/CryptoJones/AdmiralGrace/issues/271)
- [ ] Address display relative to the section, segment, function or image base — [#272](https://github.com/CryptoJones/AdmiralGrace/issues/272)
- [ ] Snippets: saved scripts bound to keys — [#273](https://github.com/CryptoJones/AdmiralGrace/issues/273)
- [ ] Extension manager with repositories, versions and dependencies — [#274](https://github.com/CryptoJones/AdmiralGrace/issues/274)
- [ ] Project file viewer and snapshot diff — [#275](https://github.com/CryptoJones/AdmiralGrace/issues/275)
- [ ] Type library explorer — [#276](https://github.com/CryptoJones/AdmiralGrace/issues/276)
- [ ] Save options: purge undo history and snapshots — [#277](https://github.com/CryptoJones/AdmiralGrace/issues/277)

### Multi-binary projects

- [ ] Projects holding several binaries and their resources — [#278](https://github.com/CryptoJones/AdmiralGrace/issues/278)
- [ ] Navigate across binaries through their imports and exports — [#279](https://github.com/CryptoJones/AdmiralGrace/issues/279)

### Collaboration

- [ ] Collaboration server: shared projects with sync and merge — [#280](https://github.com/CryptoJones/AdmiralGrace/issues/280)
- [ ] Live collaboration: chat, other users' positions, access control — [#281](https://github.com/CryptoJones/AdmiralGrace/issues/281)
- [ ] Type archives synced through the collaboration server — [#282](https://github.com/CryptoJones/AdmiralGrace/issues/282)

### Firmware analysis

- [ ] Classify firmware regions by entropy and create sections — [#283](https://github.com/CryptoJones/AdmiralGrace/issues/283)
- [ ] Detect memory-mapped I/O and RAM accesses — [#284](https://github.com/CryptoJones/AdmiralGrace/issues/284)
- [ ] Board description database for microcontrollers — [#285](https://github.com/CryptoJones/AdmiralGrace/issues/285)
- [ ] Relationships between firmware images — [#286](https://github.com/CryptoJones/AdmiralGrace/issues/286)

### Debugger

- [ ] Windows debugging: native, DbgEng, dump files and Wine — [#287](https://github.com/CryptoJones/AdmiralGrace/issues/287)
- [ ] GDB remote protocol: debug under QEMU, VMware and emulators — [#288](https://github.com/CryptoJones/AdmiralGrace/issues/288)
- [ ] Remote debugging through a debug server — [#289](https://github.com/CryptoJones/AdmiralGrace/issues/289)
- [ ] Time-travel debugging with WinDbg TTD and rr — [#290](https://github.com/CryptoJones/AdmiralGrace/issues/290)
- [ ] Time-travel queries and coverage — [#291](https://github.com/CryptoJones/AdmiralGrace/issues/291)
- [ ] Windows kernel debugging — [#292](https://github.com/CryptoJones/AdmiralGrace/issues/292)
- [ ] Conditional and hardware breakpoints and watchpoints — [#293](https://github.com/CryptoJones/AdmiralGrace/issues/293)
- [ ] Debugger panes: registers, stack, threads, modules, memory map, console — [#294](https://github.com/CryptoJones/AdmiralGrace/issues/294)
- [ ] Step by IL instruction and annotate stack variables while debugging — [#295](https://github.com/CryptoJones/AdmiralGrace/issues/295)
- [ ] Debugger scripting API and custom debug adapters — [#296](https://github.com/CryptoJones/AdmiralGrace/issues/296)
- [ ] Extract capabilities from a time-travel trace — [#297](https://github.com/CryptoJones/AdmiralGrace/issues/297)

### Objective-C and Swift

- [ ] Objective-C: resolve objc_msgSend to direct calls and drop retain and release noise — [#298](https://github.com/CryptoJones/AdmiralGrace/issues/298)
- [ ] Objective-C: constant sections, CFStrings, and cross references from selector to implementation — [#299](https://github.com/CryptoJones/AdmiralGrace/issues/299)

### AI

- [ ] AI assistant with name and type recovery tied back to the analysis — [#300](https://github.com/CryptoJones/AdmiralGrace/issues/300)

---

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/
