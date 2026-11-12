# Library identification by whole-function hash

A library function is the same code in every program that links it.
`strlen` is `strlen` whether it sits in a web server or a text editor, so
it can be named by a fingerprint of its body without lifting a line.
`ag funcid` makes the signature files that hold those fingerprints
(`create`), reads them back onto an image (`match`), and writes what a
match knows — the name, the prototype, the comment — into a project
(`apply`). Recognising library code lets the analyst skip it and spend
the session on what is unique to the program.

```sh
ag funcid list
ag funcid create /lib/x86_64-linux-gnu/libc.so.6 -o libc.agsig --library libc
ag funcid match ./program --sig libc.agsig
ag funcid apply ./program --project program.agproj --sig libc.agsig
```

## The fingerprint and its constraints

The fingerprint is a SHA-256 of the function's bytes, from its entry to
where it ends, taken after the bytes that carry an address are masked to
zero. A whole-function hash is exact: one byte different and it is a
different function. The masking is what makes it survive a change of load
address — the *constraints* on the hash.

Two kinds of operand are masked, found by decoding each instruction and
reading its constant offsets, so the exact bytes are zeroed and nothing
else:

- the relative offset of a branch — `call`, `jmp`, a conditional jump,
  `loop` — because the target moves with the load address;
- the displacement of a memory operand that is an address: a RIP-relative
  reference, or an absolute one with no base and no index register.

A stack or structure offset is **kept**: `[rbp-8]` and `[rax+0x10]` are
the shape of the function, not its placement, and the same in every copy.
The hash is domain-separated and bound to the architecture and the byte
length, so a 32-bit function never collides with a 64-bit one and a prefix
of a function never matches the whole. The result is 64 lowercase hex
characters.

Only x86 and x86-64 are masked today; on another architecture the bytes
are hashed as they stand.

## The signature file

A signature file (`.agsig`) is versioned JSON, like the project file, so
it travels between machines and stays readable without AdmiralGrace.

```jsonc
{
  "format": 1,
  "library": "libc",
  "arch": "x86-64",
  "source": "GNU C Library (Ubuntu GLIBC 2.43-2ubuntu2.4) 2.43, x86-64",
  "signatures": [
    {
      "hash": "370c7f232c8eb0baababfcc9278381ffacbe7ef135f630c29390eaef2f30ac38",
      "length": 16,
      "name": "free",
      "prototype": "void free(void *)"
    }
  ]
}
```

`format` is the format version — this program writes and reads `1`, and
refuses a newer one with a notice rather than misreading it. `library` is
the name the signatures belong to; `arch` is the architecture they were
taken from (`x86-64`, `x86`, `aarch64`, `arm`); `source` records where they
came from, for provenance. Each signature is one function: its `hash`, its
`length` in bytes, its `name`, and, when known, its `prototype` and
`comment`. Identical bodies — a thunk and its target, an alias — are one
signature, the first name at the first address keeping it.

## The commands

- `ag funcid create BINARY -o FILE [--library NAME] [--source TEXT]
  [--no-types] [--json]` — fingerprint every named function of an image
  whose functions are named: a library with symbols, such as libc.so.6, or
  any binary the analysis has named. A name the analysis made up
  (`sub_…`, `nullsub_…`) is left out — a signature is a library's own name
  for a function, not a placeholder. Unless `--no-types`, a function whose
  name the built-in type libraries know carries its prototype, rendered
  from their own types, so a libc signature holds `void free(void *)` and
  not just the name. `--library` names the file (its stem when not said);
  `--source` records provenance (the binary's path when not said).
- `ag funcid match BINARY [--sig FILE]… [--no-builtin] [--json]` — report
  the image's functions that a signature knows, in address order, each
  with its name and, when known, its prototype. The built-in databases are
  read unless `--no-builtin`; `--sig` adds more, and may be repeated.
- `ag funcid apply BINARY --project PROJECT [--sig FILE]… [--no-builtin]
  [--json]` — write what the matches know into a project: the name, the
  prototype and the comment of each matched function. A project file not
  there yet is made from the image. **The analyst's own words win**: a
  rename, a prototype or a comment already on a function stands, and a
  match only fills what is not said. Applying twice names nothing new the
  second time.
- `ag funcid list [--json]` — the signature databases the engine ships,
  with their counts and provenance.

`match` and `apply` take the same image options as the other image
commands (`--raw`, a slice), so a signature can be matched against a
carved region as well as a whole file.

## The built-in databases

The engine ships signatures for **libc**, **libstdc++** and **libgcc**,
read by `match` and `apply` unless `--no-builtin`. They are taken from real
libraries — the GNU C Library, GNU libstdc++ and GCC's libgcc — and each
file's `source` says which build. libstdc++ names are demangled
(`std::terminate()`); libgcc carries the compiler's helpers (`__multi3`,
`__ashlti3`).

A whole-function hash is exact, so a signature matches the build it was
taken from and builds that share the same code. A different compiler,
optimisation level or library version may emit different bytes and not
match. The built-ins are a starting point for the common case; `create`
makes signatures for the exact libraries a target links, and `--sig`
reads them in beside or instead of the built-ins.
