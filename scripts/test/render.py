#!/usr/bin/env python3
"""Render a config template for the LOCAL TEST: replace ${vault:...} placeholders with non-secret test values.
Usage: render.py <template> <out> [key=value ...]   (key = vault path, e.g. fs/kanidm/domain)
Secrets are never rendered here: `#file` placeholders must be given as paths of files that the test creates at run time.
Extra `--sub "OLD => NEW"` arguments replace literal text afterwards (test-only overrides such as ports); they are printed."""
import re
import sys

args = sys.argv[1:]
tpl, out = args[0], args[1]
vals, subs = {}, []
i = 2
while i < len(args):
    if args[i] == "--sub":
        k, v = args[i + 1].split(" => ", 1)
        subs.append((k, v)); i += 2
    else:
        k, v = args[i].split("=", 1)
        vals[k] = v; i += 1
text = open(tpl, encoding="utf-8").read()


def repl(m):
    key = m.group(1)
    if key not in vals:
        sys.exit(f"render: no value for placeholder {key}")
    return vals[key]


text = re.sub(r"\$\{vault:([A-Za-z][A-Za-z0-9_./#-]*)\}", repl, text)
for k, v in subs:
    if k not in text:
        sys.exit(f"render: override target not found: {k}")
    text = text.replace(k, v)
    print(f"render: test override {k!r} -> {v!r}")
open(out, "w", encoding="utf-8").write(text)
