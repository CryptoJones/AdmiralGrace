# Scripting

Repetitive analysis is scripted, and a batch runs without the workbench. The script is in
any language: it talks to `ag` over the same protocol a language model does, JSON-RPC 2.0
one message a line, and `ag run` starts it with the server on its standard streams.

## `ag run`

```bash
cargo run --bin ag -- run ./sample.elf --project ./sample.agproj -- python3 my_script.py
cargo run --bin ag -- run ./sample.elf --project ./sample.agproj -- python3 scripts/examples/tag_string_users.py 'hello|world' greeting
```

`ag run IMAGE [--project FILE] [--option NAME VALUE]… [--raw …] [--slice …] -- COMMAND ARGS…`
opens the image the way `ag image` and `ag mcp` open it — the analysis runs first — then
starts the command and speaks the tool protocol to it:

- the command's **standard output** is the server's input: a request a line;
- the command's **standard input** is the server's output: a reply a line;
- the command's **standard error** is the terminal's, so a script prints there, or into a
  file — anything printed to standard output is read as a request, and a line that is not
  JSON is answered with a parse error.

The command sees the image's path, as it was given to `ag run`, in `AG_IMAGE`, and the
project file's in `AG_PROJECT` — empty when there is none. When the command's output closes
the server stops, and `ag run` ends with the command's own exit status (128 plus the signal,
for a command a signal ended), so a script that fails fails the batch. The server answers one
request before it reads the next, so a script reads each reply before it sends another
request, as the Python client does; one that sends many requests without reading the replies
fills the pipes and waits on the server as the server waits on it. With `--project FILE` the script's
changes — names, labels, comments, bookmarks, tags, colors, cross references — are saved to
the file after every change, the same file the workbench opens; a file that is not there
yet is made from the image. Without a project file the tools that write answer with an
error saying so.

## The tools

The script calls the tools `ag mcp` serves; `docs/cli.md` lists them under *An MCP server*.
In short: `image_info`, `list_functions`, `search`, `disassemble`, `decompile`,
`control_flow`, `il`, `callers`, `callees`, `cross_references`, `strings` and `read_bytes`
read the image; `annotations`, `set_name`, `set_label`, `set_comment`, `set_bookmark`,
`bookmarks`, `set_tags`, `set_color`, `add_reference`, `remove_reference`, `tags` and
`tagged` read and write the project file. A function is named by its address or its name;
an address is hex, such as `0x1198`. `set_tags` and `set_color` take `on` — `function`,
`address` (the default) or `block` — to say what the record is on, as the workbench's
prompts do.

A conversation, as the lines go over the pipes:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"my_script","version":"1"}}}
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"ag","version":"0.35.0"},"instructions":"…"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"decompile","arguments":{"target":"main"}}}
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"int main(int argc, char **argv)\n{\n…"}],"isError":false}}
```

A tool's own failure — a function that is not there — comes back as a result with
`isError` true and the reason as its text; a request the server cannot take — an unknown
tool, arguments that are not an object — as a JSON-RPC `error`. A record's answer carries
the same data as JSON in `structuredContent`, so a script reads fields rather than text.

## The Python client: `scripts/ag.py`

`scripts/ag.py` is the conversation as Python calls, one file with no dependency but the
standard library. A script imports it from the `scripts` directory (`PYTHONPATH=scripts`) or
copies it beside itself.

```python
from ag import Session

ag = Session()                                   # initialize, on the script's stdin and stdout
for function in ag.functions(filter="^crypt")["functions"]:
    ag.set_tags(function["address_hex"], add=["crypto"], on="function")
code = ag.decompile("main")                      # the pseudocode, as text
users = ag.cross_references("0x4010")["used_by"] # a record, as a dict
```

`Session.call(tool, **arguments)` is every tool; the methods on it are the tools by name
(`info`, `functions`, `search`, `disassemble`, `decompile`, `control_flow`, `il`, `callers`,
`callees`, `cross_references`, `strings`, `read_bytes`, `annotations`, `set_name`,
`set_label`, `set_comment`, `set_bookmark`, `bookmarks`, `set_tags`, `set_color`,
`add_reference`, `remove_reference`, `tags`, `tagged`), each returning the structured answer
when there is one and the text otherwise. A tool's failure raises `ToolError` with the
tool's message; a refused request, a message the server could not read, or a conversation
that ended raises `ProtocolError`. Addresses are taken as ints or hex text. The session
reads the script's standard input as UTF-8 and moves `sys.stdout` onto standard error, so a
stray `print()` reaches the terminal and not the server.

`scripts/examples/tag_string_users.py` tags every function that uses a string matching a
pattern, bookmarks the one that uses the most, and leaves a note on it — a batch of the
things an analyst does by hand, in twenty lines. It finds the client beside itself, so it
runs from the repository as it is.

## Why a protocol and not an embedded language

The same tools serve a language model (`ag mcp`) and a script (`ag run`), so there is one
surface to keep right, and a script is written in whatever its author already has — Python,
a shell, anything that reads and writes lines. Nothing is embedded in `ag`, so the binary
stays one Rust program, and a script that needs a library has the whole language's.
