"""Author the independent eight-field native Core companion manifest owner.

This module retains the complete original native compiler/receipt protocol and
SHA implementation. HIACCM01 carries seven physical byte sequences; the HIA
owner itself computes every digest in the published eight-field manifest.
"""
from __future__ import annotations

import argparse
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

OUTPUT = "examples/hia_bootstrap/source_core_companion_manifest.hepta"
MAGIC = int.from_bytes(b"HIACCM01", "little")
COMPANIONS = ((11, "compare"), (12, "integer"), (13, "unpack"))
# The first four slots are the original compiler protocol's captured inputs.
SLOTS = (160, 176, 128, 144, 192, 208, 224)
HASH_SLOTS = (2176, 2112, None, 2048, 2240, 2304, 2368)


def owner_source():
    source = f"""
def core_word(w:mutbuf, p:u64) -> u64:
    return word_load(w, p)

def core_store(w:mutbuf, p:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, p + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def core_part_slot(index:u64) -> u64:
    if index == 0:
        return 160
    if index == 1:
        return 176
    if index == 2:
        return 128
    if index == 3:
        return 144
    return 192 + (index - 4) * 16

def admit(s:readbuf, w:mutbuf) -> u32:
    if length(s) < 72:
        return 16
    if uint(s, 0, 8) != {MAGIC}:
        return 16
    role = uint(s, 8, 8)
    if role < 11 or role > 13:
        return 16
    cursor = 72
    index = 0
    while index < 7:
        count = uint(s, 16 + index * 8, 8)
        if count == 0 or count > 1048576:
            return 16
        if cursor > length(s) or count > length(s) - cursor:
            return 16
        slot = core_part_slot(index)
        ignored = core_store(w, slot, cursor)
        ignored = core_store(w, slot + 8, count)
        cursor = cursor + count
        index = index + 1
    if cursor != length(s):
        return 16
    if core_header(s, core_word(w, 160), core_word(w, 168), role) == 0:
        return 16
    if module_header(s, core_word(w, 128), core_word(w, 136), 9) == 0:
        return 16
    ignored = core_store(w, 24, role)
    ignored = core_store(w, 32, 0)
    ignored = core_store(w, 40, cursor)
    ignored = core_store(w, 16, 2)
    return 0

def core_header(s:readbuf, p:u64, n:u64, role:u64) -> u64:
"""
    for role, family in COMPANIONS:
        prefix = f"hia-asm.v1 hepta.hia.program.v8 core_{family}\n".encode("ascii")
        source += (
            f"    if role == {role}:\n"
            f"        if n < {len(prefix)}:\n"
            "            return 0\n"
            f"        return core_header_{role}(s, p, {len(prefix)})\n"
        )
    source += "    return 0\n\n"
    source += "def core_name(o:mutbuf, p:u64, role:u64) -> u64:\n"
    for role, family in COMPANIONS:
        source += f"    if role == {role}:\n        return core_name_{role}(o, p)\n"
    source += "    return 0\n\n"
    source += """def render(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
"""
    for slot, target in ((144, 2048), (176, 2112), (160, 2176),
                         (192, 2240), (208, 2304), (224, 2368)):
        source += (
            f"    if digest(s, core_word(w, {slot}), core_word(w, {slot + 8}), o, w, {target}) == 0:\n"
            "        return 0\n"
        )
    source += """    role = core_word(w, 24)
    p = core_part_0(o, 0)
    p = append_digest(o, w, p, 2240)
    p = core_part_1(o, p)
    p = append_digest(o, w, p, 2304)
    p = core_part_2(o, p)
    p = append_digest(o, w, p, 2048)
    p = core_part_3(o, p)
    p = core_name(o, p, role)
    p = core_part_4(o, p)
    p = append_digest(o, w, p, 2112)
    p = core_part_5(o, p)
    p = core_name(o, p, role)
    p = core_part_6(o, p)
    p = append_digest(o, w, p, 2368)
    p = core_part_7(o, p)
    p = append_digest(o, w, p, 2176)
    return core_part_8(o, p)

"""
    parts = (
        b'{\n  "abi_sha256": "',
        b'",\n  "bridge_sha256": "',
        b'",\n  "compiler_sha256": "',
        b'",\n  "image_path": "core-',
        b'.image.bin",\n  "image_sha256": "',
        b'",\n  "schema": "hepta.hia.core-',
        b'-native.v1",\n  "selection_sha256": "',
        b'",\n  "source_sha256": "',
        b'"\n}\n',
    )
    for index, part in enumerate(parts):
        source += literal(f"core_part_{index}", part)
    for role, family in COMPANIONS:
        prefix = f"hia-asm.v1 hepta.hia.program.v8 core_{family}\n".encode("ascii")
        source += exact_view(f"core_header_{role}", prefix, "uint")
        source += literal(f"core_name_{role}", family.encode("ascii"))
    return source


def document():
    document = original("helper")
    document["module"] = "source_core_companion_manifest"
    function(document, "admit")["name"] = "admit_original_reference"
    function(document, "render")["name"] = "render_original_reference"
    # The original five-field minimum is too short for the complete Core value.
    # All original child compilation, exact output comparison and SHA operations
    # remain identical; only this explicit publication capacity is extended.
    constant(function(document, "helper_manifest"), "v17", 512, 1024)
    append_functions(document, owner_source())
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
            raise SystemExit("native Core companion manifest owner differs")
    else:
        path.write_bytes(raw)
    print(OUTPUT, len(raw), sha256(raw).hexdigest())


if __name__ == "__main__":
    main()
