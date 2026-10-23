# The corpus format

`ag` reads two layouts of the same analysis: an indexed corpus, and a kuna project
export. A directory holding a kuna export is detected and read as one; anything else is
read as a corpus.

## The corpus layout

A corpus is a directory holding `decompile-index.json` and one file per function. The
index is JSON: a `version`, the `target_sha256` of the binary that was analysed, the
`provider` that produced it, and a `functions` array. Each entry gives the function's
`address` and `name`, its `status`, and the byte `range` its body covers. The body itself
lives in `functions/<address>.c`, or wherever the entry's `relative_path` points.

```json
{
  "version": 1,
  "target_sha256": "9f86d0…",
  "provider": { "id": "ag-engine", "name": "AdmiralGrace", "version": "0.1.0" },
  "functions": [
    {
      "address": "0x1000",
      "name": "main",
      "status": "written",
      "body": {
        "available": true,
        "non_contiguous": false,
        "ranges": [{ "start": "0x1000", "end": "0x1010" }]
      }
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `address` | The function's entry address, as a hex string. |
| `name` | The function's name. Empty when it has none. |
| `status` | `written` when the body is there, `failed` when it is not. |
| `relative_path` | Where the body lives, relative to the corpus root. Absent means `functions/<address>.c`. |
| `body.available` | Whether the function has a body at all. |
| `body.ranges` | The byte ranges the body covers. More than one means the body is non-contiguous. |
| `body.non_contiguous` | Whether the ranges are a scatter rather than one block. |

A function with no `relative_path` is read from `functions/<address>.c`, and its leading
`//` comment header is dropped: only the body is shown.

## The kuna project export layout

An export is a directory holding the decompilation of one binary:

| File | What it holds |
|---|---|
| `<name>.c` | Every function's body, under a `// Function: <name> @ <addr>` header. |
| `<name>.h` | The recovered prototypes and the recompile prelude. |
| `<name>.asm` | The disassembly of every code section, with a label per function. |
| `index.jsonl` | Under `--stream`: one JSON record per function, giving its byte span in the `.c`. |
| `README.md` | The binary the export was made from, its sections, and the counts of what succeeded. |

A streamed export writes its `.c` in decompile order rather than address order, so a
reader that goes by position reads the wrong function. `ag` resolves every function
through the index, and falls back to the `// Function:` headers when there is no index.

The `.asm` is sliced by a function's label. The `; arg:` and `; stack:` notes sit under
the label in a plain export and in a `; --- variables ---` section in a streamed one, so
both are collected.

The `README.md` matters beyond its prose: it names the binary the export was made from,
and that path is what lets the workbench ask kuna about the binary itself.

## Reading either layout

The same commands report on both, because both are flattened into the same shape of
entry - address, name, status, range, and whether a body is there:

```sh
ag corpus --root ./corpus stats
ag corpus --root ./challenge.kuna stats
```
