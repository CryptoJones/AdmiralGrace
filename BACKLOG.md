# AdmiralGrace backlog

One list, two views: this file and the [GitHub Issues tab](https://github.com/CryptoJones/AdmiralGrace/issues) are kept in sync. Every open item here has an issue and every open issue has a line here; adding an item means filing the issue and linking it, closing an issue means checking the box.

Seeded 2026-10-23 from two sources: the code review of the engine foundation at `e9e6ced` (PR #1), and the review of [kuna](https://github.com/Noelo-Lab/kuna), the agent-first Rust port of the Ghidra decompiler. Review items are grouped; each group is one issue, and the issue carries the full repro list.

## P0 — Engine correctness (`ag-engine`)

### CFG builder — [#9](https://github.com/CryptoJones/AdmiralGrace/issues/9)
- [ ] No block splitting → **overlapping blocks**: `74 02 90 90 c3` @0x1000 (if-diamond) yields blocks `[0x1000,0x1002)` and `[0x1002,0x1005)` overlapping tail block `[0x1004,0x1005)`; backward `jne` into mid-block (`31 c0 ff c0 83 f8 0a 75 f9 c3`) overlaps the entry block. `resolve_branches` (`cfgwalk.rs` ~23–97) never checks whether the next address starts/extends an existing block.
- [ ] Dangling successor: `eb 00 c3` → block `[0x1000,0x1002)` lists successor `0x1002` but that block start is never scheduled.
- [ ] Indirect calls lose the graph: `ff d0 c3` → 1 block, no successor, `call_sites` empty; the continuation is unreachable in the CFG (catch-all arm, `cfgwalk.rs` ~87–90).
- [ ] Called targets walked into the caller's `ProcedureCfg`: `e8 …` pushes the callee onto the same frontier — callee blocks end up inside the caller; targets belong in `call_sites` only.
- [ ] Duplicate successors not filtered within a block (loop case lists target + fallthrough twice).

### Decoder instruction flow — [#10](https://github.com/CryptoJones/AdmiralGrace/issues/10)
- [ ] `ud2` / `xbegin` abort the **whole segment** decode (`FlowControl::Exception → bail!`). Real x86-64 functions carry `ud2` constantly. Expected: decode the instruction, record a trap marker, continue. Pinned test: `0f 0b c3` currently → `Err`.
- [ ] `syscall` decodes to `Flow::Call(0)` — misleading semantics.
- [ ] `Flow::Xbegin` declared but never constructed (dead variant).

### Register identity — [#11](https://github.com/CryptoJones/AdmiralGrace/issues/11)
- [ ] 8-bit GPR numbering collision: `AH` → index 4, same as `SP`/`RSP` → AH ≡ RSP in `Operands`.
- [ ] Non-GPR/XMM registers forced to index 0: every `ymm`/`zmm`/k-register collapses to the same `RegisterId`.
- [ ] Operand width dropped: `89 c0` and `48 89 c0` produce identical `Operands`.
- [ ] `RegisterSet` `1u64 << (index & 63)`: silently **aliases** any index ≥ 64 into 0 (latent until identity is fixed).

## P0 — CLI (`ag-cli`) — [#12](https://github.com/CryptoJones/AdmiralGrace/issues/12)
- [ ] Byte-boundary panics: `&types[..60]` and `name.truncate(70)` panic on multi-byte characters at the cut point (valid non-ASCII names/type encodings). Needs char-safe truncation.
- [ ] `0X1000` accepted by the resolve prefix check but rejected by `parse_addr` (only lowercase `0x` is stripped) → whole subcommand errors out.

## P0 — Silent data damage (`ag-corpus`) — [#13](https://github.com/CryptoJones/AdmiralGrace/issues/13)
- [ ] Unparseable IMP silently becomes `imp_addr 0` (`unwrap_or(0)`); hex parse also strips only lowercase `0x`.
- [ ] Class methods `+[Class sel]` rendered/stored as `-[Class sel]`; `by_name` uses that key, so collisions resolve last-write-wins via `insert`.
- [ ] Double `with_shift` desyncs `by_imp` (keys accumulate) vs `imp_addr` (current shift only); `by_name` is never re-shifted.
- [ ] `drop_header` cuts the function head at the first blank line (`"// hdr\nint f(void) {\n  int a;\n\n  return a;\n}"` → `"  return a;\n}"`); single-line headers stay glued in.
- [ ] `to_function` errors silently skipped; duplicate addresses silently keep the first entry.
- [ ] `parse_addr` rejects uppercase `0X` prefix.
- [ ] `Sha256` field is dead storage (never read).

## Hygiene (done) — [#14](https://github.com/CryptoJones/AdmiralGrace/issues/14)
- [x] `LICENSE` file missing (Cargo.toml declares MIT).
- [x] Unused dependencies: `walkdir` (workspace), `serde`/`serde_json` (`ag-engine`, `ag-cli`), `regex` (`ag-corpus`).
- [x] Dead variant: `Flow::Xbegin` (see decoder flow) — tracked in #10.

## kuna-derived work

### data layer and workbench

- [x] Add a kuna project-export provider (index.jsonl + .c/.h/.asm) to ag-corpus and ag-ui — [#4](https://github.com/CryptoJones/AdmiralGrace/issues/4)
- [x] Use kuna's JSON surfaces to fill the navigator, inspector and graph panes — [#5](https://github.com/CryptoJones/AdmiralGrace/issues/5)

### engine

- [ ] Evaluate depending on kuna-sleigh and kuna-analysis instead of a hand-written decoder and loader — [#6](https://github.com/CryptoJones/AdmiralGrace/issues/6)
- [ ] Option registry with a generated catalog and symptom index for engine decisions — [#8](https://github.com/CryptoJones/AdmiralGrace/issues/8)

### cli

- [ ] `ag install-skill` and `ag docs`: ship an agent skill and the manual inside the binary — [#7](https://github.com/CryptoJones/AdmiralGrace/issues/7)

---

Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/
