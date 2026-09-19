#!/usr/bin/env python3
"""rfc - a tiny stdlib-only MCP server (stdio, JSON-RPC 2.0) for reading RFC text.

Tools:
  rfc_get(number, section?, max_chars?)   whole RFC or one section (with subsections), e.g. "4.1.3"
  rfc_search(number, query, context?)     case-insensitive line search with the enclosing section

RFC text comes from https://www.rfc-editor.org/rfc/rfcNNNN.txt, cached in <project>/.cache/rfc/.
Registered in .mcp.json; self-test: python tools/mcp/rfc_server.py --selftest
"""
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2])
CACHE = ROOT / ".cache" / "rfc"
HEADING = re.compile(r"^((?:\d+|[A-Z])(?:\.\d+)*)\.?\s{1,4}\S")

TOOLS = [
    {
        "name": "rfc_get",
        "description": "Return the text of an RFC, or one section of it (including its subsections). "
        "Use for exact normative wording, e.g. number=9846 section='4.1.3'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "number": {"type": "integer", "description": "RFC number, e.g. 9846"},
                "section": {"type": "string", "description": "Section like '4.2.8' or 'A.1'; omit for the table of contents"},
                "max_chars": {"type": "integer", "description": "Truncate output (default 15000)"},
            },
            "required": ["number"],
        },
    },
    {
        "name": "rfc_search",
        "description": "Search an RFC for a phrase (case-insensitive); returns matching lines with their section and context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "number": {"type": "integer"},
                "query": {"type": "string"},
                "context": {"type": "integer", "description": "Lines of context (default 2)"},
            },
            "required": ["number", "query"],
        },
    },
]


def rfc_lines(n):
    path = CACHE / f"rfc{n}.txt"
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(f"https://www.rfc-editor.org/rfc/rfc{n}.txt", headers={"User-Agent": "brisk-rfc-mcp/1"})
        with urllib.request.urlopen(req, timeout=60) as r:
            path.write_bytes(r.read())
    out = []
    for ln in path.read_text("utf-8", "replace").split("\n"):
        if "\f" in ln or "[Page " in ln or re.match(r"^RFC \d{4} ", ln):
            continue  # page furniture splits paragraphs
        out.append(ln.rstrip())
    return out


def section_of(lines, i):
    for j in range(i, -1, -1):
        m = HEADING.match(lines[j])
        if m:
            return lines[j].strip()
    return "(front matter)"


def rfc_get(number, section=None, max_chars=15000):
    lines = rfc_lines(int(number))
    if not section:
        text = "\n".join(lines[:200])  # front matter + table of contents
    else:
        sec = section.strip().rstrip(".")
        start = None
        for i, ln in enumerate(lines):
            m = HEADING.match(ln)
            if m and m.group(1) == sec:  # HEADING is anchored at column 0; TOC lines are indented
                start = i
                break
        if start is None:
            return f"section {sec} not found in RFC {number}; call rfc_get without section for the TOC"
        end = len(lines)
        for i in range(start + 1, len(lines)):
            m = HEADING.match(lines[i])
            if m and not (m.group(1) + ".").startswith(sec + "."):
                end = i
                break
        text = "\n".join(lines[start:end]).strip()
    max_chars = int(max_chars or 15000)
    return text if len(text) <= max_chars else text[:max_chars] + f"\n... [truncated at {max_chars} chars]"


def rfc_search(number, query, context=2):
    lines, q, ctx, hits = rfc_lines(int(number)), query.lower(), int(context or 2), []
    for i, ln in enumerate(lines):
        if q in ln.lower():
            lo, hi = max(0, i - ctx), min(len(lines), i + ctx + 1)
            hits.append(f"[{section_of(lines, i)}] line {i + 1}:\n" + "\n".join(lines[lo:hi]))
            if len(hits) >= 30:
                hits.append("... (30 matches shown)")
                break
    return "\n\n".join(hits) if hits else f"no match for {query!r} in RFC {number}"


def handle(msg):
    method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if mid is None:
        return None  # notification (e.g. notifications/initialized)
    if method == "initialize":
        result = {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "rfc", "version": "1.0.0"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name, a = params.get("name"), params.get("arguments") or {}
        try:
            if name == "rfc_get":
                text = rfc_get(a["number"], a.get("section"), a.get("max_chars"))
            elif name == "rfc_search":
                text = rfc_search(a["number"], a["query"], a.get("context"))
            else:
                raise ValueError(f"unknown tool {name}")
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        except Exception as e:  # report tool errors to the model, keep the server alive
            result = {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main():
    if "--selftest" in sys.argv:
        head = rfc_get(9846, "7.1", 400)
        assert "Key Schedule" in head, head
        assert "tls13" in rfc_search(9846, "HkdfLabel")
        print("rfc_server selftest ok")
        return
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            resp = handle(json.loads(raw))
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
