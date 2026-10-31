"""A client for ag's tools, for a script that `ag run` starts.

`ag run IMAGE [--project FILE] -- python3 script.py` starts the script with
ag's tool server on the script's standard input and output: the script
writes a request a line and reads a reply a line, the Model Context
Protocol over JSON-RPC 2.0, the same protocol `ag mcp` speaks to a language
model. This module is that conversation as Python calls:

    from ag import Session

    ag = Session()
    for function in ag.functions(filter="^crypt")["functions"]:
        ag.set_tags(function["address_hex"], add=["crypto"], on="function")

Everything the script prints to standard output is read as a request, so a
script prints its own output to standard error, or into a file.

The module has no dependency but the standard library, and is one file, so
a script copies it beside itself, adds the `scripts` directory to `sys.path`
as the examples do, or runs with it on `PYTHONPATH`.
"""

import io
import json
import os
import sys


class ToolError(Exception):
    """A tool said no: the function is not there, the project is read-only."""


class ProtocolError(Exception):
    """The conversation itself went wrong: the server refused the request (an
    unknown tool, arguments that are not an object), could not read a message,
    answered with something that is not a reply, or ended."""


class Session:
    """One conversation with the server on the script's standard streams.

    Without a reader and a writer of its own, the session takes the script's
    standard input and output — read as UTF-8, whatever the locale — and
    moves `sys.stdout` onto standard error, so a stray `print()` reaches the
    terminal instead of the server.
    """

    def __init__(self, reader=None, writer=None):
        if reader is None:
            reader = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8")
        if writer is None:
            writer = sys.stdout
            sys.stdout = sys.stderr
            if os.environ.get("AG_IMAGE") is None:
                print(
                    "ag.py: AG_IMAGE is not set; this script is meant to be started by `ag run`",
                    file=sys.stderr,
                )
        self._reader = reader
        self._writer = writer
        self._next_id = 0
        self.server = self._request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ag.py", "version": "1"},
            },
        )
        self._notify("notifications/initialized")

    # The protocol.

    def _send(self, message):
        self._writer.write(json.dumps(message, separators=(",", ":")) + "\n")
        self._writer.flush()

    def _notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def _request(self, method, params=None):
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        while True:
            line = self._reader.readline()
            if not line:
                raise ProtocolError("the server ended the conversation")
            if not line.strip():
                continue
            try:
                reply = json.loads(line)
            except ValueError as error:
                raise ProtocolError(f"the server sent a line that is not JSON: {error}") from None
            if not isinstance(reply, dict):
                raise ProtocolError("the server sent something that is not a reply")
            if "error" in reply and reply.get("id") is None:
                # The server could not read a message: ours went out
                # glued to something, or was too long. Waiting for a reply
                # to it would wait forever.
                error = reply["error"]
                raise ProtocolError(
                    f"the server could not read a message: {error.get('message')}"
                )
            if reply.get("id") != self._next_id:
                continue
            if "error" in reply:
                error = reply["error"]
                raise ProtocolError(f"{error.get('code')}: {error.get('message')}")
            return reply["result"]

    def tools(self):
        """The tools the server offers, each with its name, description and schema."""
        return self._request("tools/list")["tools"]

    def call(self, tool, **arguments):
        """Call a tool; its structured answer when it has one, else its text.

        A tool's own failure raises ToolError with the tool's message.
        """
        result = self._request("tools/call", {"name": tool, "arguments": arguments})
        text = "".join(
            part.get("text", "") for part in result.get("content", []) if part.get("type") == "text"
        )
        if result.get("isError"):
            raise ToolError(text)
        if "structuredContent" in result:
            return result["structuredContent"]
        return text

    # The read tools.

    def info(self):
        return self.call("image_info")

    def functions(self, filter=None, limit=None):
        return self.call("list_functions", **_given(filter=filter, limit=limit))

    def search(self, query, limit=None):
        return self.call("search", **_given(query=query, limit=limit))

    def disassemble(self, target):
        return self.call("disassemble", target=str(target))

    def decompile(self, target):
        return self.call("decompile", target=str(target))

    def control_flow(self, target):
        return self.call("control_flow", target=str(target))

    def il(self, target, level="medium", ssa=False):
        """The function at one level of the lift: lifted, low, medium or high."""
        return self.call("il", target=str(target), level=level, ssa=ssa)

    def callers(self, target):
        return self.call("callers", target=str(target))

    def callees(self, target):
        return self.call("callees", target=str(target))

    def cross_references(self, target):
        return self.call("cross_references", target=str(target))

    def strings(self, filter=None, limit=None):
        return self.call("strings", **_given(filter=filter, limit=limit))

    def read_bytes(self, address, length=None):
        return self.call("read_bytes", **_given(address=_hex(address), length=length))

    # The project tools: each saves the project file at once.

    def annotations(self, address):
        return self.call("annotations", address=_hex(address))

    def set_name(self, address, name):
        return self.call("set_name", address=_hex(address), name=name)

    def set_label(self, address, name):
        return self.call("set_label", address=_hex(address), name=name)

    def set_comment(self, address, text, above=False):
        return self.call("set_comment", address=_hex(address), text=text, above=above)

    def set_bookmark(self, address, on=True):
        return self.call("set_bookmark", address=_hex(address), on=on)

    def bookmarks(self):
        return self.call("bookmarks")

    def set_tags(self, address, add=(), remove=(), on="address"):
        return self.call(
            "set_tags", address=_hex(address), add=list(add), remove=list(remove), on=on
        )

    def set_color(self, address, color, on="address"):
        return self.call("set_color", address=_hex(address), color=color or "none", on=on)

    def add_reference(self, source, target):
        return self.call("add_reference", **{"from": _hex(source), "to": _hex(target)})

    def remove_reference(self, source, target):
        return self.call("remove_reference", **{"from": _hex(source), "to": _hex(target)})

    def tags(self):
        return self.call("tags")

    def tagged(self, tag):
        return self.call("tagged", tag=tag)


def _given(**arguments):
    """The arguments that were given: a tool's schema has no place for None."""
    return {name: value for name, value in arguments.items() if value is not None}


def _hex(address):
    """An address as the tools take it: hex text, from an int or text."""
    if isinstance(address, int):
        return hex(address)
    return str(address)
