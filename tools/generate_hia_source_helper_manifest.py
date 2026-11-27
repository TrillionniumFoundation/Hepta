"""Author explicit helper protocol extensions without changing the original domains.

The complete v1 HIA sources remain fixed test inputs. HIAHLM01 and stage-4
operation 1 retain roles 1..8. HIAHLM02, stage-4 operation 2 and check mode 13
admit only the four named extension roles. The original byte limits, parser,
SHA256, compiler comparison and publication rules are retained.
"""
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg

FIXTURES = {
    "helper": ("tests/fixtures/hia_helper_catalog_original_v1/source_helper_manifest.hepta.txt", "94d466c3f0c107e5fb01f96b4b2410bb1238ad73e7c3ef7ebc2e970f1d894e1b"),
    "stage": ("tests/fixtures/hia_helper_catalog_original_v1/source_release_stage_plan.hepta.txt", "614f35f61cdad7f5759f17d2ab7b7fd40af0d9643d328ae679cc447284362f53"),
}
OUTPUTS = {
    "helper": "examples/hia_bootstrap/source_helper_manifest.hepta",
    "stage": "examples/hia_bootstrap/source_release_stage_plan.hepta",
}
# Core's 11/12/13 roles have an independent eight-field contract.
EXTENSIONS = (
    (9, "bounded_read", "bounded-read", "bounded-read", 3, 8),
    (10, "json_pretty", "json-pretty", "json-pretty", 1, 8),
    (14, "artifact_page", "artifact-page-policy", "artifact-page", 2, 9),
    (15, "json_wire", "json-wire", "json-wire", 1, 9),
)
ALLOWED = "role == 9 or role == 10 or role == 14 or role == 15"


def original(kind):
    path, digest = FIXTURES[kind]
    raw = (ROOT / path).read_bytes()
    if sha256(raw).hexdigest() != digest:
        raise ValueError("complete original helper source changed: " + kind)
    return assemble_program(raw.decode("ascii")).as_dict()


def function(document, name):
    return next(f for f in document["functions"] if f["name"] == name)


def operation(fn, name):
    rows = [o for b in fn["blocks"] for o in b["ops"]
            if any(v["name"] == name for v in o["out"])]
    if len(rows) != 1:
        raise ValueError("source operation identity changed: " + name)
    return rows[0]


def constant(fn, name, old, new):
    op = operation(fn, name)
    if op["op"] != "const" or op["attrs"] != {"value": old}:
        raise ValueError("source constant changed: " + name)
    op["attrs"]["value"] = new


def append_functions(document, source):
    nodes = ast.parse(source).body
    if not all(isinstance(n, ast.FunctionDef) for n in nodes):
        raise ValueError("function declarations required")
    signatures = {f["name"]: ([p["type"] for p in f["params"]], f["returns"][0])
                  for f in document["functions"]}
    for n in nodes:
        if n.name in signatures:
            raise ValueError("duplicate authored function: " + n.name)
        signatures[n.name] = ([a.annotation.id for a in n.args.args], n.returns.id)
    names = {name: name for name in signatures}
    functions = []
    for n in nodes:
        b = Builder(n, names, signatures)
        b.statements(n.body)
        functions.append({"name": n.name, "params": [b.param(p) for p in b.params],
                          "returns": [b.returns], "effects": ["read", "write", "trap"],
                          "entry": "b0", "blocks": b.blocks})
    compact = compact_authoring_cfg({"schema": document["schema"],
                                    "module": document["module"],
                                    "functions": deepcopy(document["functions"]) + functions})
    names = {n.name for n in nodes}
    document["functions"].extend(f for f in compact["functions"] if f["name"] in names)


def literal(name, raw):
    # The original put() writes SHA scratch at 8192 + offset. Output literals
    # use the raw byte-store primitive and never share that scratch convention.
    lines = [f"def {name}(o:mutbuf, p:u64) -> u64:"]
    lines.extend(f"    store(o, p + {i}, {value})" for i, value in enumerate(raw))
    lines.append(f"    return p + {len(raw)}")
    return "\n".join(lines) + "\n"


def exact_view(name, raw, uint):
    lines = [f"def {name}(s:readbuf, p:u64, n:u64) -> u64:",
             f"    if n != {len(raw)}:", "        return 0",
             "    if p > length(s) or n > length(s) - p:", "        return 0"]
    for offset in range(0, len(raw), 8):
        part = raw[offset:offset + 8]
        lines += [f"    if {uint}(s, p + {offset}, {len(part)}) != {int.from_bytes(part, 'little')}:",
                  "        return 0"]
    return "\n".join(lines + ["    return 1"]) + "\n"


def helper_program():
    document = original("helper")
    old_admit = function(document, "admit")
    current = deepcopy(old_admit)
    old_admit["name"] = "admit_prior"
    current["name"] = "admit_current"
    for b in old_admit["blocks"]:
        for op in b["ops"]:
            if op["op"] == "call" and op["attrs"].get("function") == "module_header":
                op["attrs"]["function"] = "module_header_prior"
    constant(current, "v15", int.from_bytes(b"HIAHLM01", "little"), int.from_bytes(b"HIAHLM02", "little"))
    constant(current, "v173", 9, 16)
    op = operation(current, "v28")
    if op["op"] != "compare.gt" or op["args"] != ["v25", "v23"]:
        raise ValueError("original helper role guard changed")
    op.update(op="call", args=["v25"], attrs={"function": "invalid_extended_role"})
    document["functions"].append(current)
    function(document, "module_header")["name"] = "module_header_prior"
    function(document, "protocol_name")["name"] = "protocol_name_prior"
    render = function(document, "render")
    calls = [o for b in render["blocks"] for o in b["ops"]
             if o["op"] == "call" and o["attrs"].get("function") == "protocol_name"]
    if len(calls) != 2:
        raise ValueError("original render call sites changed")
    calls[1]["attrs"]["function"] = "schema_name"
    tails = [o for b in render["blocks"] for o in b["ops"]
             if o["op"] == "call" and o["attrs"].get("function") == "part4"]
    if len(tails) != 1 or tails[0]["args"] != ["v51", "v67"]:
        raise ValueError("original schema suffix call changed")
    tails[0]["attrs"]["function"] = "schema_tail"
    tails[0]["args"].append("v56")
    source = f"""
def invalid_extended_role(role:u64) -> bool:
    return role != 9 and role != 10 and role != 14 and role != 15

def admit(s:readbuf, w:mutbuf) -> u32:
    if length(s) >= 8:
        if uint(s, 0, 8) == {int.from_bytes(b"HIAHLM02", "little")}:
            return admit_current(s, w)
    return admit_prior(s, w)

def module_header(s:readbuf, p:u64, n:u64, role:u64) -> u64:
    if role == 16:
        return module_header_prior(s, p, n, 9)
"""
    for role, module, image, schema, version, core in EXTENSIONS:
        prefix = f"hia-asm.v1 hepta.hia.program.v{core} {module}\n".encode("ascii")
        source += f"    if role == {role}:\n        if n < {len(prefix)}:\n            return 0\n        return header_{role}(s, p, {len(prefix)})\n"
    source += "    return 0\n\n"
    source += "def protocol_name(o:mutbuf, p:u64, role:u64) -> u64:\n"
    for role, module, image, schema, version, core in EXTENSIONS:
        source += f"    if role == {role}:\n        return extended_name_{role}(o, p)\n"
    source += "    return protocol_name_prior(o, p, role)\n\n"
    source += """def schema_name(o:mutbuf, p:u64, role:u64) -> u64:
    if role == 14:
        return page_schema_name(o, p)
    return protocol_name(o, p, role)

def schema_tail(o:mutbuf, p:u64, role:u64) -> u64:
    if role == 9:
        return version_three(o, p)
    if role == 14:
        return version_two(o, p)
    return part4(o, p)

"""
    for role, module, image, schema, version, core in EXTENSIONS:
        prefix = f"hia-asm.v1 hepta.hia.program.v{core} {module}\n".encode("ascii")
        source += exact_view(f"header_{role}", prefix, "uint")
        source += literal(f"extended_name_{role}", image.encode("ascii"))
    source += literal("page_schema_name", b"artifact-page")
    part = function(document, "part4")
    suffix = b"".join(operation(part, name)["attrs"]["value"].to_bytes(width, "little")
                      for name, width in (("v4", 8), ("v8", 8), ("v12", 8), ("v16", 8), ("v20", 1)))
    if len(suffix) != 33 or suffix.count(b"v1") != 1:
        raise ValueError("original schema suffix literal changed")
    source += literal("version_two", suffix.replace(b"v1", b"v2", 1))
    source += literal("version_three", suffix.replace(b"v1", b"v3", 1))
    append_functions(document, source)
    return document


def stage_program():
    document = original("stage")
    check = function(document, "f26")
    current = deepcopy(check)
    check["name"] = "check_prior"
    current["name"] = "check_current"
    # The wrapper admits mode 13 only to this copy. The unchanged copy keeps
    # its original 1..11 mode set and original role-9 refusal.
    constant(current, "v64", 11, 13)
    constant(current, "v470", 5, 13)
    guard = operation(current, "v497")
    if guard["op"] != "compare.gt" or guard["args"] != ["v495", "v496"]:
        raise ValueError("original checker role guard changed")
    guard.update(op="call", args=["v495"], attrs={"function": "invalid_extended_role"})
    document["functions"].append(current)
    function(document, "f21")["name"] = "frame_kind_prior"
    function(document, "f57")["name"] = "manifest_value_prior"
    source = f"""
def invalid_extended_role(role:u64) -> bool:
    return role != 9 and role != 10 and role != 14 and role != 15

def f26(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 16:
        if f23(s, 8, 8) == 13:
            return check_current(s, o, w)
    return check_prior(s, o, w)

def f21(w:mutbuf) -> u64:
    if f24(w, 128) == 4 and f24(w, 136) == 2:
        if invalid_extended_role(f24(w, 144)) or f24(w, 160) != 4:
            return 0
        f25(w, 176, 3)
        return {int.from_bytes(b"HIAHLM02", "little")}
    return frame_kind_prior(w)

def f57(s:readbuf, w:mutbuf, key:u64) -> u64:
    role = f24(w, 136)
    if role >= 1 and role <= 8:
        return manifest_value_prior(s, w, key)
    p = f24(w, 16016)
    n = f24(w, 16024)
"""
    for role, module, image, schema, version, core in EXTENSIONS:
        source += f"    if role == {role}:\n        if key == 2:\n            return image_{role}(s, p, n)\n        if key == 4:\n            return schema_{role}(s, p, n)\n        return 0\n"
    source += "    return 0\n\n"
    for role, module, image, schema, version, core in EXTENSIONS:
        source += exact_view(f"image_{role}", (image + ".image.bin").encode("ascii"), "f23")
        source += exact_view(f"schema_{role}", f"hepta.hia.{schema}-native.v{version}".encode("ascii"), "f23")
    append_functions(document, source)
    return document


def generated_files():
    return {OUTPUTS["helper"]: render_assembly(helper_program()).encode("ascii"),
            OUTPUTS["stage"]: render_assembly(stage_program()).encode("ascii")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for path, raw in generated_files().items():
        target = ROOT / path
        if args.check:
            if target.read_bytes() != raw:
                raise SystemExit("generated HIA helper catalog differs: " + path)
        else:
            target.write_bytes(raw)
        print(path, len(raw), sha256(raw).hexdigest())


if __name__ == "__main__":
    main()
