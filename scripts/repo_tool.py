#!/usr/bin/env python3
"""Repo tool shared by fs-kanidm, fs-zentinel and fs-tuwunel (standard library only; run with `python3 -I`).

  repo_tool.py check    validate mirror.toml, capabilities.toml, config/schema.toml; secrets must be placeholders;
                        generated docs and export must be up to date
  repo_tool.py docs     write docs/{en,de}/capabilities.md and docs/{en,de}/configuration.md
  repo_tool.py export   write export/config-export.json (deterministic; no values of secrets exist in the repo)

Secrets never live here (ADR 0054, ADR 0067): config files carry only ${vault:<path>} placeholders.
"""
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER = re.compile(r"\$\{vault:([A-Za-z0-9_./#-]+)\}")
SUPPORT = {"yes", "no", "unstable"}
RELATION = {"provides", "requires", "recommends"}
SECRETISH = re.compile(r"(password|passwd|secret|token|private|api[_-]?key|credential)", re.I)

LABELS = {
    "en": {
        "cap_title": "Capabilities", "cap_intro": "Capability tags for the FreeSynergy catalog (ADR 0068). `provides` = offers it, `requires` = needs it, `recommends` = can use it. Support is `yes`, `no` or `unstable`; every `yes` and `unstable` cites the upstream source. Generated from `capabilities.toml`; checked on version",
        "tag": "Tag", "rel": "Relation", "sup": "Support", "what": "Meaning", "src": "Source",
        "cfg_title": "Configuration", "cfg_intro": "Public default configuration in `{file}`. It holds placeholders only: values for secrets come from the vault (ADR 0067) when the file is rendered on the server. Generated from `config/schema.toml`.",
        "key": "Setting", "typ": "Type", "dflt": "Default", "secret": "Secret", "descr": "Description",
        "yes": "yes", "no": "no", "unstable": "unstable", "vault": "from vault",
    },
    "de": {
        "cap_title": "Fähigkeiten", "cap_intro": "Fähigkeiten-Tags für den FreeSynergy-Katalog (ADR 0068). `provides` = bietet an, `requires` = braucht, `recommends` = kann nutzen. Unterstützung ist `yes`, `no` oder `unstable` (ja, nein, instabil); jedes `yes` und `unstable` nennt die Quelle beim Hersteller. Erzeugt aus `capabilities.toml`; geprüft für Version",
        "tag": "Tag", "rel": "Beziehung", "sup": "Unterstützung", "what": "Bedeutung", "src": "Quelle",
        "cfg_title": "Konfiguration", "cfg_intro": "Öffentliche Voreinstellungen in `{file}`. Die Datei enthält nur Platzhalter: Werte für Geheimnisse kommen aus dem Tresor (ADR 0067), wenn die Datei auf dem Server erzeugt wird. Erzeugt aus `config/schema.toml`.",
        "key": "Einstellung", "typ": "Typ", "dflt": "Standard", "secret": "Geheimnis", "descr": "Beschreibung",
        "yes": "ja", "no": "nein", "unstable": "instabil", "vault": "aus dem Tresor",
    },
}


def load(name):
    with open(ROOT / name, "rb") as f:
        return tomllib.load(f)


def cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def caps_doc(lang, mirror, caps):
    L = LABELS[lang]
    out = [f"# {L['cap_title']}", "", f"{L['cap_intro']} {caps['package']['upstream']} {caps['package']['version']} ({caps['package']['checked']}).", "",
           f"| {L['tag']} | {L['rel']} | {L['sup']} | {L['what']} | {L['src']} |", "|---|---|---|---|---|"]
    for c in caps["capability"]:
        what = c.get(f"text_{lang}", c.get("text_en", ""))
        src = f"[link]({c['source']})" if c.get("source") else "-"
        out.append(f"| `{c['tag']}` | {c['relation']} | {L[c['support']]} | {cell(what)} | {src} |")
    out.append("")
    return "\n".join(out)


def cfg_doc(lang, schema):
    L = LABELS[lang]
    out = [f"# {L['cfg_title']}", ""]
    for fl in schema["file"]:
        out += [L["cfg_intro"].format(file=fl["path"]), "",
                f"| {L['key']} | {L['typ']} | {L['dflt']} | {L['secret']} | {L['descr']} |", "|---|---|---|---|---|"]
        for f in fl["field"]:
            dflt = f"`{f['default']}`" if "default" in f else "-"
            sec = f"{L['yes']} ({L['vault']}: `{f['vault']}`)" if f.get("secret") else L["no"]
            out.append(f"| `{f['key']}` | {f['type']} | {cell(dflt)} | {sec} | {cell(f.get(lang, f.get('en', '')))} |")
        out.append("")
    return "\n".join(out)


def gen_docs(mirror, caps, schema):
    files = {}
    for lang in ("en", "de"):
        files[f"docs/{lang}/capabilities.md"] = caps_doc(lang, mirror, caps)
        files[f"docs/{lang}/configuration.md"] = cfg_doc(lang, schema)
    return files


def placeholders_in(path):
    return sorted(set(PLACEHOLDER.findall(Path(path).read_text(encoding="utf-8"))))


def gen_export(mirror, caps, schema):
    files = []
    for fl in schema["file"]:
        p = ROOT / fl["path"]
        files.append({"path": fl["path"], "sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "placeholders": placeholders_in(p)})
    fields = [{"file": fl["path"], "key": f["key"], "type": f["type"], "default": f.get("default"), "secret": bool(f.get("secret")), "vault": f.get("vault")}
              for fl in schema["file"] for f in fl["field"]]
    doc = {"format": 1, "repo": mirror["repo"]["name"], "program": mirror["upstream"]["name"], "version": mirror["upstream"]["version"],
           "capabilities": [{k: c[k] for k in ("tag", "relation", "support")} for c in caps["capability"]],
           "files": files, "fields": fields,
           "note": "Configuration export without secrets. Secret values are never stored here; each placeholder names a vault path (ADR 0067)."}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def check():
    errs = []
    mirror, caps, schema = load("mirror.toml"), load("capabilities.toml"), load("config/schema.toml")
    for k in ("name", "version", "license", "homepage"):
        if k not in mirror.get("upstream", {}):
            errs.append(f"mirror.toml: [upstream] {k} missing")
    for a in mirror.get("artifact", []):
        for k in ("name", "kind", "verification"):
            if k not in a:
                errs.append(f"mirror.toml: artifact {a.get('name')} lacks {k}")
    pin = mirror.get("source", {}).get("commit") or mirror.get("source", {}).get("tag_commit")
    if pin is not None and not re.fullmatch(r"[0-9a-f]{40}", pin):
        errs.append("mirror.toml: source commit must be a full 40-character SHA")
    seen = set()
    for c in caps.get("capability", []):
        for k in ("tag", "relation", "support", "text_en", "text_de"):
            if k not in c:
                errs.append(f"capabilities.toml: {c.get('tag')} lacks {k}")
        if c.get("relation") not in RELATION:
            errs.append(f"capabilities.toml: {c.get('tag')} bad relation")
        if c.get("support") not in SUPPORT:
            errs.append(f"capabilities.toml: {c.get('tag')} bad support")
        if c.get("support") in ("yes", "unstable") and not str(c.get("source", "")).startswith("https://"):
            errs.append(f"capabilities.toml: {c.get('tag')} needs an https source")
        key = (c.get("tag"), c.get("relation"))
        if key in seen:
            errs.append(f"capabilities.toml: duplicate {key}")
        seen.add(key)
    # Secrets: only placeholders. Every secret field's vault path must appear in its file; no secret-looking literal values.
    for fl in schema["file"]:
        p = ROOT / fl["path"]
        if not p.exists():
            errs.append(f"{fl['path']} missing")
            continue
        text = p.read_text(encoding="utf-8")
        used = set(PLACEHOLDER.findall(text))
        for f in fl["field"]:
            if f.get("secret") and f.get("vault") not in used:
                errs.append(f"{fl['path']}: secret {f['key']} has no placeholder for {f.get('vault')}")
            if f.get("secret") and not f.get("vault"):
                errs.append(f"schema: secret {f['key']} has no vault path")
        for n, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith(("#", "//")) or not SECRETISH.search(s):
                continue
            m = re.search(r'(?:=|\s)\s*"([^"]*)"', s)
            if m and m.group(1) and not PLACEHOLDER.search(m.group(1)) and not m.group(1).startswith(("/", "http", "no", "false", "true")):
                if re.search(r"(password|secret|token|key)[\w-]*\s*(=|\s)\s*\"", s, re.I):
                    errs.append(f"{fl['path']}:{n}: possible literal secret (use ${{vault:...}})")
    for rel, want in gen_docs(mirror, caps, schema).items():
        have = (ROOT / rel).read_text(encoding="utf-8") if (ROOT / rel).exists() else None
        if have != want:
            errs.append(f"{rel} is out of date: run `python3 -I scripts/repo_tool.py docs`")
    for lang in ("en", "de"):
        for n in ("index.md", "mirror.md"):
            if not (ROOT / "docs" / lang / n).exists():
                errs.append(f"docs/{lang}/{n} missing")
    exp = ROOT / "export" / "config-export.json"
    if not exp.exists() or exp.read_text(encoding="utf-8") != gen_export(mirror, caps, schema):
        errs.append("export/config-export.json is out of date: run `python3 -I scripts/repo_tool.py export`")
    for e in errs:
        print("ERROR:", e)
    print("check:", "FAILED" if errs else "ok")
    return 1 if errs else 0


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "check"
    if cmd == "check":
        return check()
    mirror, caps, schema = load("mirror.toml"), load("capabilities.toml"), load("config/schema.toml")
    if cmd == "docs":
        for rel, text in gen_docs(mirror, caps, schema).items():
            (ROOT / rel).parent.mkdir(parents=True, exist_ok=True)
            (ROOT / rel).write_text(text, encoding="utf-8")
        return 0
    if cmd == "export":
        (ROOT / "export").mkdir(exist_ok=True)
        (ROOT / "export" / "config-export.json").write_text(gen_export(mirror, caps, schema), encoding="utf-8")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
