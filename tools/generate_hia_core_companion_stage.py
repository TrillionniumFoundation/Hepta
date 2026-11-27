"""Independent HIA checker for complete Core companion manifests.

The retained stage transport, JSON object framing and SHA implementation are
separate from the manifest producer. Only the explicit mode-14 / roles-11..13
domain is admitted. JSON member order, whitespace and ASCII JSON escapes retain
the installed selector's string semantics within its original 16 KiB limit.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_source_helper_manifest import (
    append_functions, constant, exact_view, function, literal, original,
)

OUTPUT = "examples/hia_bootstrap/source_core_companion_stage.hepta"
ROLES = ((11, "compare"), (12, "integer"), (13, "unpack"))
KEYS = ("compiler_sha256", "image_path", "image_sha256", "schema",
        "source_sha256", "abi_sha256", "bridge_sha256", "selection_sha256")


def checker_source():
    source = f"""
def reject_other(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    return 16

def f26(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 40 or length(s) > 67108864 or length(o) < 32:
        return 16
    if f23(s, 0, 8) != {int.from_bytes(b"HIASTC01", "little")} or f23(s, 8, 8) != 14:
        return 16
    role = f23(s, 16, 8)
    if role < 11 or role > 13 or f23(s, 24, 8) != 7 or f23(s, 32, 8) != 0:
        return 16
    f25(w, 128, 14)
    f25(w, 136, role)
    f25(w, 144, 7)
    if f27(s, w) == 0:
        return 16
    if f29(w, 0) == 0 or f29(w, 0) > 16384:
        return 16
    index = 1
    while index < 7:
        if f29(w, index) == 0 or f29(w, index) > 1048576:
            return 16
        index = index + 1
    if core_source_header(s, w, role) == 0 or f49(s, w) == 0:
        return 16
    f25(o, 0, {int.from_bytes(b"HIASTOK1", "little")})
    f25(o, 8, 14)
    f25(o, 16, role)
    f25(o, 24, f29(w, 0))
    f25(w, 88, 32)
    f25(w, 16, 3)
    return 0

def core_hex(c:u64) -> u64:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 65 and c <= 70:
        return c - 55
    if c >= 97 and c <= 102:
        return c - 87
    return 256

def f55(s:readbuf, w:mutbuf) -> u64:
    if f54(s, w, 34) == 0:
        return 0
    start = f24(w, 16000)
    end = f24(w, 16008)
    p = start
    while p < end:
        c = byte(s, p)
        if c == 34:
            f25(w, 16016, start)
            f25(w, 16024, p - start)
            f25(w, 16000, p + 1)
            return 1
        if c < 32:
            return 0
        if c == 92:
            p = p + 1
            if p >= end:
                return 0
            c = byte(s, p)
            if c == 117:
                if end - p < 5:
                    return 0
                i = 1
                while i < 5:
                    if core_hex(byte(s, p + i)) > 15:
                        return 0
                    i = i + 1
                p = p + 4
            elif c != 34 and c != 92 and c != 47 and c != 98 and c != 102 and c != 110 and c != 114 and c != 116:
                return 0
        p = p + 1
    return 0

def core_next_json(s:readbuf, w:mutbuf) -> u64:
    p = f24(w, 16056)
    end = f24(w, 16016) + f24(w, 16024)
    if p >= end:
        return 18446744073709551615
    c = byte(s, p)
    p = p + 1
    if c == 92:
        if p >= end:
            return 18446744073709551615
        c = byte(s, p)
        p = p + 1
        if c == 117:
            if end - p < 4:
                return 18446744073709551615
            value = 0
            i = 0
            while i < 4:
                digit = core_hex(byte(s, p + i))
                if digit > 15:
                    return 18446744073709551615
                value = (value << 4) | digit
                i = i + 1
            c = value
            p = p + 4
        elif c == 98:
            c = 8
        elif c == 102:
            c = 12
        elif c == 110:
            c = 10
        elif c == 114:
            c = 13
        elif c == 116:
            c = 9
        elif c != 34 and c != 92 and c != 47:
            return 18446744073709551615
    f25(w, 16056, p)
    return c

def core_match_json(s:readbuf, w:mutbuf, size:u64) -> u64:
    f25(w, 16056, f24(w, 16016))
    index = 0
    while index < size:
        if core_next_json(s, w) != byte(w, 17000 + index):
            return 0
        index = index + 1
    if f24(w, 16056) != f24(w, 16016) + f24(w, 16024):
        return 0
    return 1

def f50(s:readbuf, w:mutbuf) -> u64:
    if f55(s, w) == 0:
        return 0
    key = f56(s, w)
    if key == 0 or key > 8:
        return 0
    bit = 1 << (key - 1)
    seen = f24(w, 16040)
    if (seen & bit) != 0:
        return 0
    f25(w, 16040, seen | bit)
    if f54(s, w, 58) == 0 or f55(s, w) == 0:
        return 0
    if key == 2 or key == 4:
        return f57(s, w, key)
    part = 0
    if key == 1:
        part = 3
    elif key == 3:
        part = 2
    elif key == 5:
        part = 1
    else:
        part = key - 2
    return f51(s, w, part)

def f51(s:readbuf, w:mutbuf, part:u64) -> u64:
    f25(w, 48000, f28(w, part))
    f25(w, 48008, f29(w, part))
    f25(w, 48016, 0)
    f46(s, w)
    f25(w, 16056, f24(w, 16016))
    index = 0
    while index < 32:
        value = byte(w, 48032 + index)
        if core_next_json(s, w) != f52(value >> 4):
            return 0
        if core_next_json(s, w) != f52(value & 15):
            return 0
        index = index + 1
    if f24(w, 16056) != f24(w, 16016) + f24(w, 16024):
        return 0
    return 1

def f56(s:readbuf, w:mutbuf) -> u64:
"""
    for number, key in enumerate(KEYS, 1):
        source += (f"    size = core_key_{number}(w, 17000) - 17000\n"
                   f"    if core_match_json(s, w, size) != 0:\n        return {number}\n")
    source += "    return 0\n\n"
    source += """def f57(s:readbuf, w:mutbuf, key:u64) -> u64:
    role = f24(w, 136)
"""
    for role, family in ROLES:
        source += (f"    if role == {role}:\n"
                   f"        if key == 2:\n            size = core_image_{role}(w, 17000) - 17000\n"
                   f"        elif key == 4:\n            size = core_schema_{role}(w, 17000) - 17000\n"
                   "        else:\n            return 0\n"
                   "        return core_match_json(s, w, size)\n")
    source += "    return 0\n\n"
    source += """def core_source_header(s:readbuf, w:mutbuf, role:u64) -> u64:
    p = f28(w, 1)
    n = f29(w, 1)
"""
    for role, family in ROLES:
        prefix = f"hia-asm.v1 hepta.hia.program.v8 core_{family}\n".encode("ascii")
        source += (f"    if role == {role}:\n"
                   f"        if n < {len(prefix)}:\n            return 0\n"
                   f"        return core_header_{role}(s, p, {len(prefix)})\n")
    source += "    return 0\n\n"
    for number, key in enumerate(KEYS, 1):
        source += literal(f"core_key_{number}", key.encode("ascii"))
    for role, family in ROLES:
        source += literal(f"core_image_{role}", f"core-{family}.image.bin".encode("ascii"))
        source += literal(f"core_schema_{role}", f"hepta.hia.core-{family}-native.v1".encode("ascii"))
        prefix = f"hia-asm.v1 hepta.hia.program.v8 core_{family}\n".encode("ascii")
        source += exact_view(f"core_header_{role}", prefix, "f23")
    return source


def document():
    document = original("stage")
    document["module"] = "source_core_companion_stage"
    entry = function(document, "f0")
    changed = []
    for block in entry["blocks"]:
        for op in block["ops"]:
            if op["op"] == "call" and op["attrs"].get("function") in ("f1", "f16"):
                changed.append(op["attrs"]["function"])
                op["attrs"]["function"] = "reject_other"
    if sorted(changed) != ["f1", "f16"]:
        raise ValueError("original stage entry boundaries changed")
    for name in ("f26", "f50", "f51", "f55", "f56", "f57"):
        function(document, name)["name"] = name + "_original_reference"
    parser = function(document, "f49")
    constant(parser, "v4", 2048, 16384)
    constant(parser, "v34", 5, 8)
    constant(parser, "v89", 31, 255)
    append_functions(document, checker_source())
    functions = {f["name"]: f for f in document["functions"]}
    reachable, pending = set(), ["f0"]
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        if name not in functions:
            raise ValueError("missing Core checker callee: " + name)
        reachable.add(name)
        pending.extend(op["attrs"]["function"] for block in functions[name]["blocks"]
                       for op in block["ops"] if op["op"] == "call")
    document["functions"] = [f for f in document["functions"] if f["name"] in reachable]
    if sum(len(f["blocks"]) for f in document["functions"]) >= 1536:
        raise ValueError("Core checker exceeds the original compiler capacity")
    return document


def generated():
    return render_assembly(document()).encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    raw = generated()
    path = ROOT / OUTPUT
    if args.check:
        if path.read_bytes() != raw:
            raise SystemExit("native Core companion checker differs")
    else:
        path.write_bytes(raw)
    print(OUTPUT, len(raw), sha256(raw).hexdigest())


if __name__ == "__main__":
    main()
