"""Native exact-bytes Core prelude, with no foreign JSON object bridge.

The immutable byte capture, ambient integer-string limit and bounded storage
are foreign mechanics. HIA owns UTF-8, complete JSON preflight, integer lexical
limits, canonicalization and primitive/composite namespace routing. Composite
elaboration, typed Python values and the remaining public plan owner are not
claimed by this component.
"""
from __future__ import annotations
import ast
import argparse
import json
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_canonical import SOURCE as CANONICAL_SOURCE
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC = int.from_bytes(b"HIACBR01", "little")
RESULT_MAGIC = int.from_bytes(b"HIACBF01", "little")
MESSAGES = {
    2: "invalid/deep UTF-8 JSON",
    3: "program exceeds byte budget",
    4: "program exceeds structural budget before JSON allocation",
    5: ("historical nominal v2 requires import_legacy_composite_v2; "
        "the primitive v2 namespace cannot infer a producer profile"),
}
SOURCE = r'''
def core_bytes(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 256 or length(w) < 128:
        return 4294967293
    if get(w, 0) != REQUEST_MAGIC or get(w, 8) != 1:
        return 4294967293
    if get(w, 32) != 0 or get(w, 40) != 0 or get(w, 48) != 0 or get(w, 56) != 0:
        return 4294967293
    original_size = get(w, 16)
    digit_limit = get(w, 24)
    captured = choose(original_size > 8388609, 8388609, original_size)
    if length(s) != captured:
        return 4294967293
    if original_size > 8388608:
        return publish_error(o, 3, original_size, digit_limit, 0)
    if full_utf8(s) == 0:
        return publish_error(o, 2, original_size, digit_limit, 1)
    put(o, 48, 262144)
    put(o, 56, 64)
    result = widen(decode_json(s, w, o))
    if result == 4294967294:
        return publish_error(o, 4, original_size, digit_limit, 2)
    if result == 4294967295 or result == 4294967292:
        return publish_error(o, 2, original_size, digit_limit, 2)
    if result == 4294967293:
        return 4294967293
    if integer_limit(s, w, digit_limit) == 0:
        return publish_error(o, 2, original_size, digit_limit, 3)
    count = get(w, 8)
    size = widen(emit_canonical(s, o, w))
    if size == 0 or size > original_size or size > length(o) - 64:
        return 4294967293
    route = namespace_route(w)
    if route == 2:
        return publish_error(o, 5, original_size, digit_limit, 4)
    i = size
    while i > 0:
        i = i - 1
        store(o, 64 + i, byte(o, i))
    return publish_frame(o, route, size, count, original_size, digit_limit, 5)

def full_utf8(s:readbuf) -> u64:
    i = 0
    while i < length(s):
        after = utf8_next(s, i)
        if after == 0:
            return 0
        i = after
    return 1

def utf8_next(s:readbuf, index:u64) -> u64:
    size = length(s)
    ch = byte(s, index)
    index = index + 1
    if ch < 128:
        return index
    needed = 0
    minimum = 0
    cp = 0
    if ch >= 194 and ch <= 223:
        needed = 1
        minimum = 128
        cp = ch & 31
    if ch >= 224 and ch <= 239:
        needed = 2
        minimum = 2048
        cp = ch & 15
    if ch >= 240 and ch <= 244:
        needed = 3
        minimum = 65536
        cp = ch & 7
    if needed == 0 or index + needed > size:
        return 0
    count = 0
    while count < needed:
        ch = byte(s, index)
        if ch < 128 or ch > 191:
            return 0
        cp = cp * 64 + (ch & 63)
        index = index + 1
        count = count + 1
    if cp < minimum or cp > 1114111:
        return 0
    if cp >= 55296 and cp <= 57343:
        return 0
    return index

def integer_limit(s:readbuf, w:mutbuf, maximum:u64) -> u64:
    if maximum == 0:
        return 1
    i = 0
    count = get(w, 8)
    while i < count:
        record = 64 + i * 56
        if get(w, record) == 3:
            start = get(w, record + 24)
            size = get(w, record + 32)
            if byte(s, start) == 45:
                size = size - 1
            if size > maximum:
                return 0
        i = i + 1
    return 1

def namespace_route(w:mutbuf) -> u64:
    if get(w, 64) != 6:
        return 0
    node = get(w, 64 + 24)
    schema = 18446744073709551615
    types = False
    while node != 18446744073709551615:
        record = 64 + node * 56
        if span_is(w, get(w, record + 40), get(w, record + 48), 0) == 1:
            schema = node
        if span_is(w, get(w, record + 40), get(w, record + 48), 1) == 1:
            types = True
        node = get(w, record + 16)
    if schema == 18446744073709551615:
        return 0
    record = 64 + schema * 56
    if get(w, record) != 4:
        return 0
    start = get(w, record + 24)
    size = get(w, record + 32)
    if span_is(w, start, size, 2) == 1 and types:
        return 2
    if span_is(w, start, size, 3) == 1 or span_is(w, start, size, 4) == 1 or span_is(w, start, size, 5) == 1 or span_is(w, start, size, 6) == 1:
        return 1
    return 0

def publish_frame(o:mutbuf, status:u64, size:u64, nodes:u64, original_size:u64, digit_limit:u64, stage:u64) -> u32:
    put(o, 8, 1)
    put(o, 16, status)
    put(o, 24, size)
    put(o, 32, nodes)
    put(o, 40, original_size)
    put(o, 48, digit_limit)
    put(o, 56, stage)
    put(o, 0, RESULT_MAGIC)
    return 64 + size

def publish_error(o:mutbuf, status:u64, original_size:u64, digit_limit:u64, stage:u64) -> u32:
    start = message_start(status)
    size = message_size(status)
    if size == 0 or size > length(o) - 64:
        return 4294967293
    i = 0
    while i < size:
        at = start + i
        word = message_word(at >> 3)
        store(o, 64 + i, (word >> ((at & 7) * 8)) & 255)
        i = i + 1
    return publish_frame(o, status, size, 0, original_size, digit_limit, stage)
'''

DECODE_PREFIX = r'''
if length(w) < 128 or length(o) < 128 or length(o) < length(s):
    return 4294967293
maximum = get(w, 48)
maximum_depth = get(w, 56)
put(o, 48, maximum)
put(o, 56, maximum_depth)
result = widen(decode_json(s, w, o))
if result >= 4294967292:
    return result
'''

def _literal_functions():
    names = ("schema", "types", "hepta.hia.program.v2",
             "hepta.hia.composite.v1", "hepta.hia.composite.v2",
             "hepta.hia.composite.v3", "hepta.hia.composite.v4")
    lines = [
        "def span_is(w:mutbuf, start:u64, size:u64, which:u64) -> u64:",
        "    if size != literal_size(which):", "        return 0",
        "    at = literal_start(which)", "    i = 0", "    while i < size:",
        "        word = literal_word((at + i) >> 3)",
        "        expected = (word >> (((at + i) & 7) * 8)) & 255",
        "        if byte(w, start + i) != expected:", "            return 0",
        "        i = i + 1", "    return 1",
    ]
    for prefix, values in (("literal", dict(enumerate(names))), ("message", MESSAGES)):
        pool = bytearray()
        offsets = {}
        for code, text in values.items():
            raw = text.encode("ascii")
            offsets[code] = (len(pool), len(raw))
            pool.extend(raw)
        for suffix, index in (("start", 0), ("size", 1)):
            lines += ["", "def %s_%s(code:u64) -> u64:" % (prefix, suffix)]
            for code, pair in offsets.items():
                lines += ["    if code == %d:" % code, "        return %d" % pair[index]]
            lines += ["    return 0"]
        lines += ["", "def %s_word(index:u64) -> u64:" % prefix]
        for start in range(0, len(pool), 8):
            word = int.from_bytes(pool[start:start + 8].ljust(8, b"\0"), "little")
            lines += ["    if index == %d:" % (start // 8), "        return %d" % word]
        lines += ["    return 0", ""]
    return "\n".join(lines)

def source_program():
    source = SOURCE.replace("REQUEST_MAGIC", str(REQUEST_MAGIC)).replace("RESULT_MAGIC", str(RESULT_MAGIC))
    canonical = ast.parse(CANONICAL_SOURCE)
    function = canonical.body[0]
    prefix = ast.parse(DECODE_PREFIX).body
    if function.name != "canonical_json" or ast.dump(ast.Module(body=function.body[:len(prefix)], type_ignores=[]),
            include_attributes=False) != ast.dump(ast.Module(body=prefix, type_ignores=[]), include_attributes=False):
        raise ValueError("canonical decoder prelude identity differs")
    function.name = "emit_canonical"
    function.body = function.body[len(prefix):]
    # Only the existing decoding prelude is removed: the complete canonical
    # traversal and all sorting/escaping helpers remain exactly the same AST.
    return source + "\n" + _literal_functions() + "\n" + ast.unparse(canonical) + "\n" + decoder_source()


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError("duplicate byte-prelude authoring name")
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name],
            "params": [builder.param(value) for value in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"],
            "entry": "b0", "blocks": builder.blocks})
    return compact_authoring_cfg({"schema": "hepta.hia.program.v8",
                                  "module": "core_bytes", "functions": functions})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    path = args.output or Path(__file__).resolve().parents[1] / "examples/hia_bootstrap/core_bytes.hepta"
    raw = render_assembly(document()).encode()
    if args.output is None:
        path.write_bytes(raw)
    else:
        with path.open("xb") as stream:
            stream.write(raw)
    print(path.name, len(raw))


if __name__ == "__main__":
    main()
