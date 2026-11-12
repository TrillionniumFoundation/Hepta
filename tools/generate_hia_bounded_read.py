"""Generate the HIA bounded-file continuation and its source-owned entry ABI.

HIA schedules observation order, branches, ownership masks, temporary unwind
and reverse-fast-local release. CPython Path/IO/context effects remain hosted.
The preserved r4b HIA bytes have finite development evidence; regeneration and
source admission are separate from native equivalence or cold qualification.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b"HIARDB03", "little")
ABI = 0xfffffffd
TERMINAL = (1 << 64) - 1
LITERALS = (
    "input must be a bounded ordinary file",
    "input exceeds byte limit",
    "E_HIA_EDIT: cannot read ordinary input",
)
CONSTANTS = {
    "MAGIC": MAGIC, "ABI": ABI, "TERMINAL": TERMINAL,
    "PATH": 1, "O_RDONLY": 2, "O_NOFOLLOW": 3, "BIT_OR": 4,
    "O_NONBLOCK": 5, "FDOPEN_FUNCTION": 6, "OPEN_FUNCTION": 7,
    "CALL2": 8, "FDOPEN_CALL": 9, "CONTEXT_ENTER": 10,
    "FSTAT_FUNCTION": 11, "FILENO_FUNCTION": 12, "CALL0": 13,
    "CALL1": 14, "ISREG_FUNCTION": 15, "ST_MODE": 16,
    "TRUTH": 17, "ST_SIZE": 18, "GREATER": 19, "READ_FUNCTION": 20,
    "ADD_ONE": 21, "CONTEXT_EXIT": 22, "LENGTH": 23,
    "CALL_REJECT": 24, "CONTEXT_ERROR": 25, "IS_OSERROR": 26,
    "UNBOUND_PAYLOAD": 27, "UNWIND_TEMPORARIES": 28,
}
SOURCE = r'''
def bounded_read(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 64 or length(o) != 24 or length(w) != 1024:
        return ABI
    if word(s, 0) != MAGIC:
        return ABI
    if get(w, 0) == 0:
        if word(s, 8) != 0 or word(s, 16) != 0 or word(s, 24) != 0:
            return ABI
        if word(s, 32) != 0 or word(s, 40) != 0 or word(s, 48) == 0 or word(s, 56) == 0:
            return ABI
        put(w, 0, MAGIC)
        put(w, 8, 0)
        put(w, 16, 0)
        put(w, 24, 0)
        put(w, 32, 0)
        put(w, 40, 0)
        put(w, 48, 0)
        put(w, 64, word(s, 48))
        put(w, 72, word(s, 56))
        put(w, 120, 0)
        put(w, 184, 3)
        put(w, 192, 0)
        return ask(w, PATH, get(w, 64), 0, 0, 1, 8)
    if get(w, 0) != MAGIC or get(w, 24) == TERMINAL:
        return ABI
    if word(s, 8) != get(w, 8) or word(s, 16) != get(w, 16):
        return ABI
    if word(s, 24) > 1 or word(s, 40) > 1 or word(s, 48) != 0 or word(s, 56) != 0:
        return ABI
    if word(s, 24) == 1:
        if word(s, 32) == 0:
            return ABI
        return failed(o, w, word(s, 32))
    pc = get(w, 24)
    x = word(s, 32)
    if pc == 90:
        if word(s, 40) == 1:
            n = literal(w, 2)
            return done(o, w, 3, get(w, 32), n)
        return done(o, w, 2, get(w, 32), 0)
    if pc == 91:
        put(w, 32, 0)
        lifetime_plan(w)
        return ask(w, UNWIND_TEMPORARIES, 0, 0, 0, 94, 0)
    if pc == 93:
        return failed_after(o, w)
    if pc == 94:
        return after_close(w)
    if pc == 80:
        return ask(w, READ_FUNCTION, get(w, 96), 0, 0, 23, 0)
    if pc == 81:
        return done(o, w, 1, get(w, 120), 0)
    if pc == 92:
        return ABI
    if pc <= 15:
        return opening(s, o, w)
    return reading(s, o, w)

def opening(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 24)
    x = word(s, 32)
    if pc == 1:
        put(w, 64, x)
        put(w, 40, 1)
        return ask(w, O_RDONLY, 0, 0, 0, 2, 0)
    if pc == 2:
        put(w, 80, x)
        return ask(w, O_NOFOLLOW, 0, 0, 0, 3, 0)
    if pc == 3:
        return ask(w, BIT_OR, get(w, 80), x, 0, 4, 3)
    if pc == 4:
        put(w, 80, x)
        return ask(w, O_NONBLOCK, 0, 0, 0, 5, 0)
    if pc == 5:
        return ask(w, BIT_OR, get(w, 80), x, 0, 6, 3)
    if pc == 6:
        put(w, 80, x)
        put(w, 184, get(w, 184) | 4)
        return ask(w, FDOPEN_FUNCTION, 0, 0, 0, 7, 0)
    if pc == 7:
        put(w, 144, x)
        return ask(w, OPEN_FUNCTION, 0, 0, 0, 8, 0)
    if pc == 8:
        return ask(w, CALL2, x, get(w, 64), get(w, 80), 9, 1)
    if pc == 9:
        put(w, 104, x)
        return ask(w, FDOPEN_CALL, get(w, 144), x, 0, 10, 3)
    if pc == 10:
        put(w, 56, x)
        return ask(w, CONTEXT_ENTER, x, 0, 0, 11, 1)
    if pc == 11:
        put(w, 96, x)
        put(w, 184, get(w, 184) | 8)
        put(w, 48, 1)
        return ask(w, FSTAT_FUNCTION, 0, 0, 0, 12, 0)
    if pc == 12:
        put(w, 160, x)
        return ask(w, FILENO_FUNCTION, get(w, 96), 0, 0, 13, 0)
    if pc == 13:
        return ask(w, CALL0, x, 0, 0, 14, 1)
    if pc == 14:
        return ask(w, CALL1, get(w, 160), x, 0, 15, 3)
    if pc == 15:
        put(w, 112, x)
        put(w, 184, get(w, 184) | 16)
        return ask(w, ISREG_FUNCTION, 0, 0, 0, 16, 0)
    return ABI

def reading(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 24)
    x = word(s, 32)
    if pc == 16:
        put(w, 168, x)
        return ask(w, ST_MODE, get(w, 112), 0, 0, 17, 0)
    if pc == 17:
        return ask(w, CALL1, get(w, 168), x, 0, 18, 3)
    if pc == 18:
        return ask(w, TRUTH, x, 0, 0, 19, 1)
    if pc == 19:
        if word(s, 40) == 0:
            return reject(w, 0)
        return ask(w, ST_SIZE, get(w, 112), 0, 0, 20, 0)
    if pc == 20:
        return ask(w, GREATER, x, get(w, 72), 0, 21, 1)
    if pc == 21:
        return ask(w, TRUTH, x, 0, 0, 22, 1)
    if pc == 22:
        if word(s, 40) == 1:
            return reject(w, 0)
        return ask(w, READ_FUNCTION, get(w, 96), 0, 0, 23, 0)
    if pc == 23:
        put(w, 128, x)
        return ask(w, ADD_ONE, get(w, 72), 0, 0, 24, 0)
    if pc == 24:
        return ask(w, CALL1, get(w, 128), x, 0, 25, 3)
    if pc == 25:
        put(w, 120, x)
        put(w, 184, get(w, 184) | 32)
        put(w, 48, 0)
        return ask(w, CONTEXT_EXIT, get(w, 56), 0, 0, 26, 0)
    if pc == 26:
        return after_close(w)
    if pc == 27:
        return ask(w, GREATER, x, get(w, 72), 0, 28, 1)
    if pc == 28:
        return ask(w, TRUTH, x, 0, 0, 29, 1)
    if pc == 29:
        if word(s, 40) == 1:
            return reject(w, 1)
        return done(o, w, 1, get(w, 120), 0)
    return ABI

def after_close(w:mutbuf) -> u32:
    if get(w, 120) == 0:
        return ask(w, UNBOUND_PAYLOAD, 0, 0, 0, 92, 0)
    return ask(w, LENGTH, get(w, 120), 0, 0, 27, 0)

def failed(o:mutbuf, w:mutbuf, exception:u64) -> u32:
    pc = get(w, 24)
    put(w, 32, exception)
    if pc == 93 or pc == 94:
        return done(o, w, 2, exception, 0)
    put(w, 192, pc)
    lifetime_plan(w)
    return ask(w, UNWIND_TEMPORARIES, exception, 0, 0, 93, 0)

def failed_after(o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 192)
    exception = get(w, 32)
    if get(w, 40) == 0 or pc == 90:
        return done(o, w, 2, exception, 0)
    if get(w, 48) == 1:
        put(w, 48, 0)
        return ask(w, CONTEXT_ERROR, get(w, 56), exception, 0, 91, 0)
    return ask(w, IS_OSERROR, exception, 0, 0, 90, 0)

def lifetime_plan(w:mutbuf) -> u64:
    bits = get(w, 184)
    put(w, 304, 0)
    put(w, 312, 0)
    put(w, 320, 0)
    put(w, 328, 0)
    put(w, 336, get(w, 72))
    put(w, 344, get(w, 64))
    if (bits & 32) != 0:
        put(w, 304, get(w, 120))
    if (bits & 16) != 0:
        put(w, 312, get(w, 112))
    if (bits & 8) != 0:
        put(w, 320, get(w, 96))
    if (bits & 4) != 0:
        put(w, 328, get(w, 80))
    return 0

def reject(w:mutbuf, which:u64) -> u32:
    n = literal(w, which)
    if which == 0:
        return ask(w, CALL_REJECT, 512, n, 0, 80, 0)
    return ask(w, CALL_REJECT, 512, n, 0, 81, 0)

def ask(w:mutbuf, opcode:u64, a:u64, b:u64, c:u64, pc:u64, ownership:u64) -> u32:
    put(w, 8, opcode)
    put(w, 16, get(w, 16) + 1)
    put(w, 24, pc)
    put(w, 256, a)
    put(w, 264, b)
    put(w, 272, c)
    put(w, 280, ownership)
    return 1

def done(o:mutbuf, w:mutbuf, kind:u64, value:u64, size:u64) -> u32:
    lifetime_plan(w)
    put(w, 24, TERMINAL)
    put(o, 0, kind)
    put(o, 8, value)
    put(o, 16, size)
    return 0

def word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''

def literal_function():
    lines = ["def literal(w:mutbuf, which:u64) -> u64:"]
    for index, text in enumerate(LITERALS):
        raw = text.encode("utf-8")
        lines.append(f"    if which == {index}:")
        lines.extend(f"        store(w, {512 + i}, {value})" for i, value in enumerate(raw))
        lines.append(f"        return {len(raw)}")
    lines.append("    return 0")
    return "\n".join(lines) + "\n"

def source_program():
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node
    module = ast.parse(SOURCE + "\n" + literal_function())
    return ast.unparse(ast.fix_missing_locations(Expand().visit(module))) + "\n"

def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name],
            "params": [builder.param(v) for v in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"],
            "entry": "b0", "blocks": builder.blocks})
    return compact_authoring_cfg({"schema": "hepta.hia.program.v8",
        "module": "bounded_read", "functions": functions})

SOURCE_PATH = "examples/hia_bootstrap/bounded_read.hiaasm"
ABI_PATH = "hepta/hia_bounded_read_abi.json"


def entry_abi(assembly):
    return {
        "schema": "hepta.hia.bounded-read-entry-abi.v1",
        "source": SOURCE_PATH,
        "source_sha256": sha256(assembly).hexdigest(),
        "manifest_schema": "hepta.hia.bounded-read-native.v3",
        "function": "f0",
        "parameters": [
            {"name": "v0", "type": "readbuf", "bytes": 64},
            {"name": "v1", "type": "mutbuf", "bytes": 24},
            {"name": "v2", "type": "mutbuf", "bytes": 1024},
        ],
        "returns": ["u32"],
        "statuses": {"terminal": 0, "effect_requested": 1, "protocol_refusal": ABI},
        "packet_magic_ascii": "HIARDB03",
        "packet_word_bytes": 8,
        "packet_byte_order": "little",
        "foreign_effect_count": 28,
        "terminal_kinds": {"return": 1, "rethrow": 2, "convert_oserror": 3},
        "ordinary_default_input_bytes": 8 << 20,
        "limit_argument_remains_foreign": True,
        "reference_release_schedule": "CPython-3.14.4",
        "filesystem_and_context_operations_remain_hosted": True,
        "arbitrary_foreign_object_equivalence_proved": False,
        "production_activated": False,
    }


def generated_files():
    assembly = render_assembly(document()).encode("utf-8")
    abi = (json.dumps(entry_abi(assembly), sort_keys=True, indent=2) + "\n").encode("utf-8")
    return {SOURCE_PATH: assembly, ABI_PATH: abi}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, raw in generated_files().items():
        path = ROOT / name
        if args.check:
            if path.read_bytes() != raw:
                raise SystemExit("generated bounded-read source differs: " + name)
        else:
            path.write_bytes(raw)
        print(name, len(raw))


if __name__ == "__main__":
    main()
