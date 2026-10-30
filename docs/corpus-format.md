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
| `address` | The function's entry address, as a hex string. An address outside the default space names its space first — `EXTERNAL:0x1` is the address `0x1` in the `EXTERNAL` space — and the space is kept and displayed. |
| `name` | The function's name. Empty when it has none. |
| `status` | `written` when the body is there, `failed` when it is not. |
| `relative_path` | Where the body lives, relative to the corpus root. Absent means `functions/<address>.c`. |
| `body.available` | Whether the function has a body at all. |
| `body.ranges` | The byte ranges the body covers. More than one means the body is non-contiguous. |
| `body.non_contiguous` | Whether the ranges are a scatter rather than one block. |

A function with no `relative_path` is read from `functions/<address>.c`. Its header — the
run of `//` comment lines at the top of the file — is dropped, and the body is kept
whole: the signature and the locals are part of the body, and are never dropped with
the header.

## The method map

The `--methods` option lays a map of Objective-C methods over a corpus. The map is a
JSON array of records, each naming the IMP of a method, the class it belongs to, its
selector and its types:

```json
[
  { "imp": "0x1000", "class": "NSString", "sel": "length", "types": "Q" },
  { "imp": "0x2000", "class": "+NSString", "sel": "alloc", "types": "@16@0:8" }
]
```

A class method is the instance method of the class's metaclass. A map says which it is
with `"is_class_method": true`, or by writing the class with a leading `+`; a map that
says neither is read as instance methods, which is what such a map holds. The two are
told apart in the display — `-[Class sel]` for an instance method, `+[Class sel]` for a
class method — so they are two names and not one.

`--shift` gives the image-base shift: a corpus address is the IMP plus the shift. The
shift is applied once, however many times it is given.

## What the loaders say

Nothing is dropped in silence. A record that cannot be read — an address that is not an
address — is skipped and named, and two records that claim one address are both kept,
with the first resolving it. The same holds for the method map: a record whose IMP is
not an address is skipped and named. `ag` prints what it had to say on stderr, and the
workbench shows it in the Problems pane.

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
