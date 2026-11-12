# Library identification by whole-function hash

A library function is the same code in every program that links it.
`strlen` is `strlen` whether it sits in a web server or a text editor, so
it can be named by a fingerprint of its body without lifting a line.
`ag funcid` makes the signature files that hold those fingerprints
(`create`), reads them back onto an image (`match`), and writes what a
match knows — the name, the prototype, the comment — into a project
(`apply`). The signatures can be shared: `serve` runs a signature server,
`push` and `pull` move signature files to and from it, and `--server`
matches an image against it. Recognising library code lets the analyst
skip it and spend the session on what is unique to the program.

```sh
ag funcid list
ag funcid create /lib/x86_64-linux-gnu/libc.so.6 -o libc.agsig --library libc
ag funcid match ./program --sig libc.agsig
ag funcid apply ./program --project program.agproj --sig libc.agsig

ag funcid serve --store /srv/agsig                   # on the shared host
ag funcid push libc.agsig --server http://sigs:7395  # give the team your signatures
ag funcid match ./program --server http://sigs:7395  # match against everyone's
ag funcid pull --server http://sigs:7395 -o sigs/    # or take them offline
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
  read unless `--no-builtin`; `--sig` adds more, and may be repeated. When
  several signatures know one function, the first consulted is the match
  and the rest are named as **alternatives** — the text report lists them
  as `also NAME (LIBRARY)`, and the JSON carries the chosen `library`
  beside an `alternatives` array. `apply` takes the first candidate; the
  workbench is where the choice between them is made.
- `ag funcid apply BINARY --project PROJECT [--sig FILE]… [--no-builtin]
  [--json]` — write what the matches know into a project: the name, the
  prototype and the comment of each matched function. A project file not
  there yet is made from the image. **The analyst's own words win**: a
  rename, a prototype or a comment already on a function stands, and a
  match only fills what is not said. Applying twice names nothing new the
  second time.
- `ag funcid list [--json]` — the signature databases the engine ships,
  with their counts and provenance. With `--server URL`, the libraries a
  signature server holds instead.
- `ag funcid serve`, `push`, `pull`, and `--server URL` on `match` and
  `apply` — the shared signature server, below.

`match` and `apply` take the same image options as the other image
commands (`--raw`, a slice), so a signature can be matched against a
carved region as well as a whole file.

## The signature server

A team that reverses the same kind of target keeps meeting the same
libraries. A signature server is one store of signatures that everyone
pushes what they have made to, and matches against, so a library one
analyst has fingerprinted is recognised in everyone's images.

```sh
# On the shared host: serve a directory of signature files.
AG_FUNCID_TOKEN=… ag funcid serve --store /srv/agsig --listen 10.0.0.5:7395

# On an analyst's machine.
export AG_FUNCID_TOKEN=…
ag funcid push libfoo.agsig libbar.agsig --server http://10.0.0.5:7395
ag funcid list --server http://10.0.0.5:7395
ag funcid match ./program --server http://10.0.0.5:7395
ag funcid apply ./program --project program.agproj --server http://10.0.0.5:7395
ag funcid pull --server http://10.0.0.5:7395 --library libfoo -o sigs/
```

- `ag funcid serve --store DIR [--listen ADDR] [--token TOKEN]
  [--private]` — run a server over `DIR` until it is stopped. The store is
  a directory of ordinary signature files, one a library and architecture
  (`libc@x86-64.agsig`); it is made when not there, and signature files
  already in it — copied in by hand as much as pushed — are served. The
  server listens on `127.0.0.1:7395` unless `--listen` says otherwise
  (port `0` takes a free one), and its first line of output is the address
  it is listening on.
- `ag funcid push FILE… --server URL [--token TOKEN] [--json]` — send
  signature files for the server to **merge** into the libraries they
  name. A hash the server does not hold is *added*. A hash it already
  holds keeps the name it has — the first to name a function stands, so a
  push never renames what others already match — and only has a missing
  prototype or comment *filled*, when the push gives it the same name. The
  report counts what was added, filled and already known. Pushing the same
  file twice adds nothing the second time.
- `ag funcid pull --server URL [--library NAME]… [--arch ARCH] [-o DIR]
  [--token TOKEN] [--json]` — write the server's libraries into `DIR` (the
  current directory when not said) as signature files, to match against
  offline with `--sig`. All of them unless `--library` or `--arch` narrow
  it; a library the server does not hold is an error.
- `ag funcid match … --server URL` and `ag funcid apply … --server URL` —
  ask the server about the image's functions as well. What is on this
  machine is consulted first — the built-ins, then each `--sig` — and the
  server after, so the server names the functions nothing local knows and
  is offered as an alternative for the ones something does. `--server` may
  be repeated.
- `ag funcid list --server URL [--json]` — the libraries the server holds.

**What leaves the machine.** A match sends the server the *hashes* of the
image's named functions and the architecture, and nothing else — not the
bytes, not the names, not the file. The hash is a SHA-256 of the masked
body, so the server learns only whether it already knows a function. A
push sends the signature file as it is: hashes, lengths, names,
prototypes, comments and the `source` line.

**Who may do what.** A push must carry the server's **token**, given to
`serve` and to the clients with `--token` or — better, since a command
line is visible to other users of a machine — in the `AG_FUNCID_TOKEN`
environment variable. A server started without a token is **read-only**:
it serves its store and refuses every push. Listing, pulling and matching
need no token unless the server is started `--private`, when every request
does. The server refuses a library or architecture name that is not a
plain name (letters, digits and `. _ + -`), a hash that is not a hash, and
a request larger than it reads, and a client checks what a server sends it
the same way.

**The wire is plain HTTP.** The server and client carry no TLS: hashes,
signatures and the token travel unencrypted, and `https://` addresses are
refused. Keep the server on the loopback (the default), a private network
or a VPN, or reach it through an SSH tunnel:

```sh
ssh -N -L 7395:127.0.0.1:7395 sigs.example &
ag funcid match ./program --server http://127.0.0.1:7395
```

The protocol is small JSON over HTTP/1.1, so a script can speak it:

| Request | Answer |
|---|---|
| `GET /v1` | the service's name, protocol version, and whether it is writable and private |
| `GET /v1/libraries` | every library held: `library`, `arch`, `source`, `signatures` (a count) |
| `GET /v1/libraries/LIBRARY/ARCH` | that library's signature file |
| `POST /v1/libraries` with a signature file | merges it; `library`, `arch`, `added`, `filled`, `known`, `total` |
| `POST /v1/match` with `{"arch": "x86-64", "hashes": ["…"]}` | `{"databases": […]}` — a signature file a library, holding only the hashes asked for |

The token goes in an `Authorization: Bearer TOKEN` header. An error is a
status with `{"error": "…"}`. One match request carries at most 100,000
hashes; the client sends a larger image's in several.

## In the workbench

The workbench identifies library code as it opens a program image: every
function's body is hashed and looked up in the built-in signatures, off
the UI thread beside the call graph. A function a signature knows is
**highlighted** so the analyst can skip it and read what is unique:

- the navigator marks it with a `lib` pill and reads its name in green;
- the listing washes the function's body in a faint green, beneath the
  analyst's own highlights, which always stand over it;
- the file bar names the library it matched.

The inspector's **Library match** card says what the signatures know.
When several know the function — a CRT stub whose bytes libc, libstdc++
and libgcc share, say — the card is a **chooser**: one row per signature,
each naming its library, its name, and the prototype and comment it knows.
Clicking a row applies that signature's identity to the function as the
analyst's annotation. An explicit choice **overwrites** whatever the
function carried before, unlike `apply`, which only fills what is not
said. The row the workbench already shows is marked, and the choice is
undone and redone like any other mark.

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
