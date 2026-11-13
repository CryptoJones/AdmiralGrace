# AdmiralGrace UI

This directory holds the AdmiralGrace desktop workbench: an [Iced](https://iced.rs) application that reads a decompilation corpus through the same data layer the `ag` CLI uses. `UI_PLAN.md` is the product and interaction plan it is built from.

## Files

- `UI_PLAN.md` — product goals, reference review, layout, workflows, roadmap, and decisions.
- `wireframe.html` — a self-contained static desktop-screen mockup with sample data. It is a layout reference; the application is implemented in Iced.
- `src/` — the workbench crate (`ag-ui`).

## Run it

```sh
# From the repository root
cargo run --bin ag-ui

# Open a corpus
cargo run --bin ag-ui -- --corpus ./corpus

# Overlay an Objective-C method map
cargo run --bin ag-ui -- --corpus ./corpus --methods ./corpus/methods.json

# Open a program image
cargo run --bin ag-ui -- --binary ./sample.elf

# The same with an engine option set (`ag catalog` lists them)
cargo run --bin ag-ui -- --binary ./sample.elf --option loop-form while
```

A corpus directory must contain a `decompile-index.json`. From the File menu the workbench asks for a path and refuses a directory without that index. With no corpus on the command line it opens a bundled sample so the interface can be explored. A path that is not a file is refused the same way.

| Tab | What you see |
| --- | --- |
| Listing | Native x86 disassembly, 32-bit or 64-bit as the image's language says. |
| Graph | One box per block, one arrow per way the code goes on. A taken branch is told from the fall-through by the same rule as `ag image cfg`. An arrow that skips a row runs in a lane beside the blocks. |
| Bytes | Sixteen bytes a row: address, hex, ASCII. The selected instruction is marked. |
| Strings | The text the image carries, and the functions that use it. The list filters as you type. |

The navigator lists the symbols. The inspector shows the sections, the entry point, and, for a picked string, the functions that use it. The full pane guide is [docs/workbench.md](../docs/workbench.md).

<p align="center"><img src="../images/navy/helmet.jpg" alt="A diving helmet and a coil of rope, drawn as 1950s Navy clipart" width="180"></p>

## Shape of the code

- `src/main.rs` — argument parsing and the Iced application entry point.
- `src/app.rs` — application state, messages, the update loop, and the keyboard shortcuts.
- `src/data/` — the `Provider` trait and its implementations: `corpus` (a real corpus), `binary` (a program image read by the engine), `kuna` (a kuna project export), `sample` (the bundled demo project), and `empty` (no project open).
- `src/model/` — the shared selection, navigation history, project identity, and the capability flags that tell the views what a provider can supply.
- `src/views/` — the panes: menu bar, header, navigator, work surface, inspector, bottom workspace, status bar, and the inline path prompt. The graph of a function is in `src/views/graph.rs`: the layout of the blocks is pure and tested, and the canvas on top of it draws them.

Providers advertise capabilities, so a corpus that only carries pseudocode shows an honest empty state for listing and bytes instead of a blank panel.

## Open the mockup

Open `wireframe.html` in a browser. It has no dependencies and does not connect to the repository or load binaries.
