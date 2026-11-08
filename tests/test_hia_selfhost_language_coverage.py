"""Finite, feature-complete witnesses for the declared Selfhost-Core v8 language.

The Python side constructs ordinary input assembly and independent mathematical/
Core-VM observations before B0. Native B3 and mutated M3 compile every native
fixture. A finite witness inventory is not a proof of all accepted inputs.

Persist all generations, inputs, outputs and raw child logs:
  python -B tests/test_hia_selfhost_language_coverage.py --output NEW_REPORT.json

unittest uses HIA_SELFHOST_LANGUAGE_EVIDENCE when set; otherwise a temporary
evidence directory is removed only after its tests finish.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

COVERAGE_PATH = "docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json"
SELF_PATH = "tests/test_hia_selfhost_language_coverage.py"
PROFILE = "selfhost-core-linux-x86_64-v8"
WIDTHS = {"u8": 8, "u32": 32, "u64": 64, "usize": 64}
BINARY_INTEGER = ("int.add.wrap", "int.sub.wrap", "int.mul.wrap", "bit.and", "bit.or", "bit.xor")
CHECKED_ARITHMETIC = ("int.add.checked", "int.sub.checked")
NEW_INTEGER = ("bit.not", *CHECKED_ARITHMETIC)
SHIFTS = ("int.shl.checked", "int.shr.checked")
COMPARISONS = ("compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge")
INPUT_OPCODES = tuple(sorted(("const", *BINARY_INTEGER, *NEW_INTEGER, *SHIFTS, *COMPARISONS,
    "bool.and", "bool.or", "bool.not", "int.cast", "buffer.len", "buffer.load",
    "buffer.store", "buffer.swap", "call", "select")))
NATIVE = (platform.system() == "Linux"
          and platform.machine().lower() in {"x86_64", "amd64"}
          and bool(shutil.which("ld")))
HEADER = ("hia-asm.v1 hepta.hia.program.v8 selfhost\n"
    "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
    "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n")


def digest(data):
    return sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def scalar_cases():
    """Boundary witnesses are specified independently of the HIA encoder."""
    rows = []
    def add(group, typ, op, args, expected, result_type=None, mode=None):
        row = {"id": group + "-" + str(sum(x["group"] == group for x in rows)),
               "group": group, "operand_type": typ, "opcode": op,
               "arguments": args, "result_type": result_type or typ, "expected": expected}
        if mode is not None:
            row["mode"] = mode
        rows.append(row)
    for typ, width in WIDTHS.items():
        mask, high = (1 << width) - 1, 1 << (width - 1)
        for value in (0, 1, high - 1, high, mask):
            add("scalar-" + typ, typ, "const", [], value)
        alternating = int.from_bytes(bytes([0x55]) * (width // 8), "little")
        pairs = ((0, 0), (0, 1), (1, 0), (mask, 1), (mask, mask),
                 (high, 1), (high, high), (mask - 1, 2), (alternating, mask ^ alternating))
        for op in BINARY_INTEGER:
            for a, b in pairs:
                value = {"int.add.wrap": lambda: a + b, "int.sub.wrap": lambda: a - b,
                         "int.mul.wrap": lambda: a * b, "bit.and": lambda: a & b,
                         "bit.or": lambda: a | b, "bit.xor": lambda: a ^ b}[op]() & mask
                add("scalar-" + typ, typ, op, [a, b], value)
        for value in (0, 1, high - 1, high, mask, alternating):
            add("scalar-" + typ, typ, "bit.not", [value], mask ^ value)
        checked_pairs = {
            "int.add.checked": ((0, 0), (0, mask), (mask, 0), (1, mask - 1),
                (mask - 1, 1), (high - 1, 1), (high, high - 1),
                (alternating, mask ^ alternating)),
            "int.sub.checked": ((0, 0), (mask, 0), (mask, mask), (1, 1),
                (mask, 1), (high, 1), (high, high - 1), (mask, high), (alternating, 0)),
        }
        for op, operands in checked_pairs.items():
            for a, b in operands:
                value = a + b if op == "int.add.checked" else a - b
                if not 0 <= value <= mask:
                    raise AssertionError("positive checked arithmetic oracle is out of range")
                add("scalar-" + typ, typ, op, [a, b], value)
        for op in SHIFTS:
            for a, b in ((0, 0), (1, 0), (1, width - 1), (high, width - 1),
                         (mask, 1), (mask, width - 1)):
                value = ((a << b) if op == "int.shl.checked" else (a >> b)) & mask
                add("scalar-" + typ, typ, op, [a, b], value)
        for op in COMPARISONS:
            for a, b in ((0, 0), (0, 1), (1, 0), (mask, mask), (high, 1),
                         (1, high), (high, high), (mask, mask - 1)):
                value = {"compare.eq": a == b, "compare.ne": a != b,
                         "compare.lt": a < b, "compare.le": a <= b,
                         "compare.gt": a > b, "compare.ge": a >= b}[op]
                add("scalar-" + typ, typ, op, [a, b], value, "bool")
    for typ, width in WIDTHS.items():
        mask, high = (1 << width) - 1, 1 << (width - 1)
        for condition in (False, True):
            for left, right in ((0, mask), (mask, 0), (high, high - 1), (1, mask - 1)):
                add("scalar-" + typ, typ, "select", [condition, left, right], left if condition else right)
    for condition in (False, True):
        for left in (False, True):
            for right in (False, True):
                add("boolean", "bool", "select", [condition, left, right], left if condition else right)
    for value in (False, True):
        add("boolean", "bool", "const", [], value)
        add("boolean", "bool", "bool.not", [value], not value)
    for op in ("bool.and", "bool.or"):
        for a in (False, True):
            for b in (False, True):
                add("boolean", "bool", op, [a, b], (a and b) if op == "bool.and" else (a or b))
    for source, sw in WIDTHS.items():
        for target, tw in WIDTHS.items():
            for value in (0, 1, (1 << (sw - 1)) - 1, 1 << (sw - 1), (1 << sw) - 1):
                add("cast", source, "int.cast", [value], value & ((1 << tw) - 1), target, "wrap")
    return rows


class Assembly:
    """A fixture writer, not a compiler or an alternate admission path."""
    def __init__(self, serial=3):
        self.lines = []
        self.serial = serial

    def emit(self, typ, op, args=(), attrs=None):
        name = "v" + str(self.serial)
        self.serial += 1
        suffix = " " + json.dumps(attrs, separators=(",", ":")) if attrs else ""
        self.lines.append("  " + name + ":" + typ + " = " + op + "(" + ",".join(args) + ")" + suffix)
        return name

    def const(self, typ, value):
        return self.emit(typ, "const", attrs={"value": value})

    def effect(self, op, args):
        self.lines.append("  _ = " + op + "(" + ",".join(args) + ")")

    def result(self, case):
        args = [self.const("bool" if case["opcode"] == "select" and i == 0 else case["operand_type"], value)
                for i, value in enumerate(case["arguments"])]
        if case["opcode"] == "const":
            return self.const(case["result_type"], case["expected"])
        attrs = {"mode": case["mode"]} if "mode" in case else None
        return self.emit(case["result_type"], case["opcode"], args, attrs)

    def text(self):
        return "\n".join(self.lines) + "\n"


def scalar_reference_source(case):
    a = Assembly(0)
    result = a.result(case)
    return ("hia-asm.v1 hepta.hia.program.v8 language_reference\n"
        "fn f0() -> (" + case["result_type"] + ") effects(read,write,trap) entry(b0)\n"
        "block b0()\n" + a.text() + "  ret(" + result + ")\nend\n").encode()


def scalar_fixture(group, rows, *, input_arguments=False):
    a = Assembly()
    input_bytes = bytearray()
    for index, case in enumerate(rows):
        if input_arguments:
            if case["opcode"] not in NEW_INTEGER or case["operand_type"] != rows[0]["operand_type"]:
                raise ValueError("dynamic fixture needs one integer type and a new scalar operation")
            args = []
            for value in case["arguments"]:
                offset = a.const("usize", len(input_bytes))
                args.append(a.emit(case["operand_type"], "call", ["v0", offset], {"function": "f3"}))
                input_bytes.extend(value.to_bytes(WIDTHS[case["operand_type"]] // 8, "little"))
            result = a.emit(case["result_type"], case["opcode"], args)
        else:
            result = a.result(case)
        if case["result_type"] == "bool":
            word = a.emit("u64", "call", [result], {"function": "f1"})
        else:
            word = a.emit("u64", "int.cast", [result], {"mode": "wrap"})
        offset = a.const("usize", index * 8)
        a.emit("u32", "call", ["v1", offset, word], {"function": "f2"})
    size = a.const("u32", len(rows) * 8)
    bool_helper = ("fn f1(v0:bool) -> (u64) effects(read,write,trap) entry(b0)\n"
        "block b0(v0:bool)\n  branch v0 b1() b2()\n"
        'block b1()\n  v1:u64 = const() {"value":1}\n  ret(v1)\n'
        'block b2()\n  v2:u64 = const() {"value":0}\n  ret(v2)\nend\n')
    word = Assembly(3)
    for byte in range(8):
        amount = word.const("u64", byte * 8)
        shifted = word.emit("u64", "int.shr.checked", ["v2", amount])
        value = word.emit("u8", "int.cast", [shifted], {"mode": "wrap"})
        delta = word.const("usize", byte)
        offset = word.emit("usize", "int.add.wrap", ["v1", delta])
        word.effect("buffer.store", ["v0", offset, value])
    returned = word.const("u32", 0)
    word_helper = ("fn f2(v0:mutbuf,v1:usize,v2:u64) -> (u32) effects(read,write,trap) entry(b0)\n"
        "block b0(v0:mutbuf,v1:usize,v2:u64)\n" + word.text() + "  ret(" + returned + ")\nend\n")
    input_helper = ""
    if input_arguments:
        typ = rows[0]["operand_type"]
        reader = Assembly(2)
        combined = reader.const(typ, 0)
        for byte in range(WIDTHS[typ] // 8):
            delta = reader.const("usize", byte)
            offset = reader.emit("usize", "int.add.wrap", ["v1", delta])
            value = reader.emit("u8", "buffer.load", ["v0", offset])
            widened = reader.emit(typ, "int.cast", [value], {"mode": "wrap"})
            amount = reader.const(typ, byte * 8)
            shifted = reader.emit(typ, "int.shl.checked", [widened, amount])
            combined = reader.emit(typ, "bit.or", [combined, shifted])
        input_helper = ("fn f3(v0:readbuf,v1:usize) -> (" + typ + ") effects(read,write,trap) entry(b0)\n"
            "block b0(v0:readbuf,v1:usize)\n" + reader.text() + "  ret(" + combined + ")\nend\n")
    source = (HEADER + a.text() + "  ret(" + size + ")\nend\n" + bool_helper + word_helper + input_helper).encode()
    return {"id": group, "kind": "scalar", "source": source, "input": bytes(input_bytes),
            "input_arguments": input_arguments,
            "capacity": len(rows) * 8, "workspace_size": 0,
            "expected_result": len(rows) * 8,
            "expected_output": b"".join(struct.pack("<Q", int(row["expected"])) for row in rows),
            "case_ids": [row["id"] for row in rows]}


def boundary_fixture(label, source, expected=7):
    return {"id": label, "kind": "boundary", "source": source, "input": b"",
            "capacity": 8, "workspace_size": 0, "expected_result": expected,
            "expected_output": bytes([0xa5]) * 8, "case_ids": [label]}


def simple_source(value=7, variable=3):
    return (HEADER + f'  v{variable}:u32 = const() {{"value":{value}}}\n'
            f"  ret(v{variable})\nend\n").encode()


def block_source(counts):
    lines = []
    for fn, count in enumerate(counts):
        if fn == 0:
            lines.append(HEADER)
            serial = 3
        else:
            lines.append(f"fn f{fn}() -> (u32) effects(read,write,trap) entry(b0)\nblock b0()\n")
            serial = 0
        for block in range(count):
            if block:
                lines.append(f"block b{block}()\n")
            if block + 1 < count:
                lines.append(f"  jump b{block + 1}()\n")
            else:
                lines.append(f'  v{serial}:u32 = const() {{"value":7}}\n  ret(v{serial})\n')
        lines.append("end\n")
    return "".join(lines).encode()


def parameter_source(count):
    a = Assembly()
    args = [a.const("u8", i) for i in range(count)]
    result = a.emit("u32", "call", args, {"function": "f1"})
    params = ",".join("v" + str(i) + ":u8" for i in range(count))
    b = Assembly(count)
    current = "v0"
    for i in range(1, count):
        current = b.emit("u8", "int.add.wrap", [current, "v" + str(i)])
    returned = b.emit("u32", "int.cast", [current], {"mode": "wrap"})
    return (HEADER + a.text() + "  ret(" + result + ")\nend\n"
        + "fn f1(" + params + ") -> (u32) effects(read,write,trap) entry(b0)\n"
        + "block b0(" + params + ")\n" + b.text() + "  ret(" + returned + ")\nend\n").encode()


def buffer_fixture():
    a = Assembly()
    indices = [a.const("usize", i) for i in range(8)]
    for destination, resource in enumerate(("v0", "v1", "v2")):
        length = a.emit("usize", "buffer.len", [resource])
        byte = a.emit("u8", "int.cast", [length], {"mode": "wrap"})
        a.effect("buffer.store", ["v1", indices[destination], byte])
    first = a.emit("u8", "buffer.load", ["v0", indices[0]])
    last = a.emit("u8", "buffer.load", ["v0", indices[3]])
    a.effect("buffer.store", ["v1", indices[3], first])
    a.effect("buffer.store", ["v1", indices[4], last])
    observed = a.emit("u8", "buffer.load", ["v1", indices[4]])
    a.effect("buffer.store", ["v2", indices[0], observed])
    workspace = a.emit("u8", "buffer.load", ["v2", indices[0]])
    a.effect("buffer.store", ["v1", indices[5], workspace])
    a.effect("buffer.swap", ["v1", indices[3], indices[4]])
    result = a.const("u32", 8)
    source = (HEADER + a.text() + "  ret(" + result + ")\nend\n").encode()
    return {"id": "borrowed-buffer-operations", "kind": "buffer", "source": source,
            "input": bytes([0x12, 0x7f, 0x80, 0xfe]), "capacity": 8, "workspace_size": 5,
            "expected_result": 8, "expected_output": bytes([4, 8, 5, 0xfe, 0x12, 0xfe, 0xa5, 0xa5]),
            "case_ids": ["buffer.len-readbuf", "buffer.len-mutbuf", "buffer.load-readbuf",
                         "buffer.load-mutbuf", "buffer.store-mutbuf", "buffer.swap-mutbuf"]}


def buffer_reference_source(fixture):
    """Only a general-Core owner wrapper is added; native body bytes are kept."""
    a = Assembly(0)
    owners, loans = [], []
    for initial in (fixture["input"], bytes([0xa5]) * fixture["capacity"],
                    bytes(fixture["workspace_size"])):
        length = a.const("usize", len(initial))
        owner = a.emit("buffer", "buffer.new", [length])
        loan = a.emit("mutbuf", "borrow.mut", [owner])
        for i, value in enumerate(initial):
            index, byte = a.const("usize", i), a.const("u8", value)
            a.effect("buffer.store", [loan, index, byte])
        owners.append(owner)
        loans.append(loan)
    a.effect("loan.end", [loans[0]])
    loans[0] = a.emit("readbuf", "borrow.read", [owners[0]])
    a.emit("u32", "call", loans, {"function": "f0"})
    returned = []
    for i in range(fixture["capacity"]):
        index = a.const("usize", i)
        returned.append(a.emit("u8", "buffer.load", [loans[1], index]))
    for loan in loans:
        a.effect("loan.end", [loan])
    for owner in owners:
        a.effect("owner.drop", [owner])
    wrapper = ("hia-asm.v1 hepta.hia.program.v8 language_reference\n"
        "fn reference_entry() -> (" + ",".join(["u8"] * len(returned)) + ") effects(alloc,read,write,trap) entry(b0)\n"
        "block b0()\n" + a.text() + "  ret(" + ",".join(returned) + ")\nend\n")
    body = fixture["source"].decode().split("\n", 1)[1]
    return (wrapper + body).encode()


def select_input_fixtures():
    """Same native program per type, with both condition and values from input."""
    fixtures = []
    for typ, width in WIDTHS.items():
        a = Assembly()
        zero8 = a.const("u8", 0)
        flag = a.emit("u8", "buffer.load", ["v0", a.const("usize", 0)])
        condition = a.emit("bool", "compare.ne", [flag, zero8])
        operands = []
        for base in (1, 9):
            value = a.const("u64", 0)
            for index in range(8):
                byte = a.emit("u8", "buffer.load", ["v0", a.const("usize", base + index)])
                word = a.emit("u64", "int.cast", [byte], {"mode": "wrap"})
                shifted = a.emit("u64", "int.shl.checked", [word, a.const("u64", index * 8)])
                value = a.emit("u64", "bit.or", [value, shifted])
            operands.append(a.emit(typ, "int.cast", [value], {"mode": "wrap"}))
        selected = a.emit(typ, "select", [condition, *operands])
        word = a.emit("u64", "int.cast", [selected], {"mode": "wrap"})
        for index in range(8):
            shifted = a.emit("u64", "int.shr.checked", [word, a.const("u64", index * 8)])
            byte = a.emit("u8", "int.cast", [shifted], {"mode": "wrap"})
            a.effect("buffer.store", ["v1", a.const("usize", index), byte])
        result = a.emit("u32", "int.cast", [selected], {"mode": "wrap"})
        source = (HEADER + a.text() + "  ret(" + result + ")\nend\n").encode()
        mask, high = (1 << width) - 1, 1 << (width - 1)
        for i, (flag, left, right) in enumerate(((0, 0, mask), (1, mask, 0),
                (0, high, high - 1), (1, high, mask), (255, mask - 1, 1))):
            expected = left if flag else right
            fixtures.append({"id": "select-input-" + typ + "-" + str(i), "kind": "buffer",
                "source": source, "input": bytes([flag]) + struct.pack("<QQ", left, right),
                "capacity": 8, "workspace_size": 0, "expected_result": expected & 0xffffffff,
                "expected_output": struct.pack("<Q", expected), "case_ids": ["select-" + typ]})
    a = Assembly()
    zero = a.const("u8", 0)
    values = []
    for index in range(3):
        byte = a.emit("u8", "buffer.load", ["v0", a.const("usize", index)])
        values.append(a.emit("bool", "compare.ne", [byte, zero]))
    selected = a.emit("bool", "select", values)
    source = HEADER + a.text() + "  branch " + selected + " b1(v1) b2(v1)\n"
    for block, serial, value in ((1, 1000, 1), (2, 1010, 0)):
        a = Assembly(serial + 1)
        a.effect("buffer.store", ["v" + str(serial), a.const("usize", 0), a.const("u8", value)])
        result = a.const("u32", value)
        source += "block b" + str(block) + "(v" + str(serial) + ":mutbuf)\n" + a.text() + "  ret(" + result + ")\n"
    source = (source + "end\n").encode()
    for condition in (0, 1):
        for left in (0, 1):
            for right in (0, 1):
                expected = left if condition else right
                fixtures.append({"id": f"select-input-bool-{condition}{left}{right}", "kind": "buffer",
                    "source": source, "input": bytes([condition, left, right]), "capacity": 8,
                    "workspace_size": 0, "expected_result": expected,
                    "expected_output": bytes([expected]) + bytes([0xa5]) * 7, "case_ids": ["select-bool"]})
    return fixtures


def positive_fixtures():
    rows = scalar_cases()
    groups = list(dict.fromkeys(row["group"] for row in rows))
    fixtures = [scalar_fixture(group, [row for row in rows if row["group"] == group])
                for group in groups]
    fixtures += [scalar_fixture("dynamic-integer-" + typ,
        [row for row in rows if row["operand_type"] == typ and row["opcode"] in NEW_INTEGER],
        input_arguments=True) for typ in WIDTHS]
    fixtures += select_input_fixtures()
    fixtures += [buffer_fixture(), boundary_fixture("parameters-16", parameter_source(16), 120),
                 boundary_fixture("blocks-per-function-256", block_source([256])),
                 boundary_fixture("blocks-total-1536", block_source([256] * 6)),
                 boundary_fixture("ssa-index-2047", simple_source(variable=2047))]
    spaced = simple_source().replace(b",", b" , ").replace(b" = ", b"   =   ")
    spaced = spaced.replace(b'{"value":7}', b'{ "value" : 7 }')
    fixtures.append(boundary_fixture("optional-ascii-spaces", spaced))
    # Distribute spaces across real lines: the independent assembly frontend
    # also has a 16 KiB per-line transport limit, separate from the 1 MiB source bound.
    lines = block_source([256] * 6).splitlines(keepends=True)
    remaining = (1 << 20) - sum(map(len, lines))
    per_line, extra = divmod(remaining, len(lines))
    padded = b"".join(b" " * (per_line + int(i < extra)) + line for i, line in enumerate(lines))
    fixtures.append(boundary_fixture("source-bytes-1048576", padded))
    return fixtures


def rejected_fixtures():
    """A rejected Core program is distinct from valid Core outside v8."""
    from tools.qualify_hia_selfhost import SAMPLE, invalid_sources
    from tools.hia_selfhost_cases import (backward_chain_source, scalar_function,
                                         call_graph_invalid_sources, recursion_refusals)
    from tools.hia_selfhost_resources import swap_refusals
    from tools.hia_selfhost_tailcalls import tail_refusals
    rows = {}
    def add(name, source, boundary, general_core=None):
        rows[name] = {"id": name, "source": source, "boundary": boundary,
                      "general_core_expected": general_core}
    for name, source in invalid_sources(SAMPLE.read_bytes()).items():
        add("existing-" + name, source, "grammar, types, SSA, control and resource admission", "rejected")
    for name, source in call_graph_invalid_sources(SAMPLE.read_bytes()).items():
        add("call-" + name, source, "exact direct-call signature/target", "rejected")
    for name, source in recursion_refusals().items():
        add("recursion-" + name, source, "v6 checked tail-self-only recursion", "accepted")
    for name, source in swap_refusals().items():
        add("swap-" + name, source, "mutbuf, usize indices, zero results, exact arity", "rejected")
    # Existing tail witnesses are independently classified by their own helper.
    for name, (source, general_core) in tail_refusals().items():
        add("tail-" + name, source, "immediate exact tail return and mutable arguments",
            "accepted" if general_core else "rejected")
    selection = (HEADER + '  v3:bool = const() {"value":true}\n'
        '  v4:u32 = const() {"value":1}\n  v5:u32 = const() {"value":2}\n'
        '  v6:u8 = const() {"value":3}\n  v7:bool = const() {"value":false}\n')
    invalid_selections = [("arity-" + str(n), "v8:u32", ",".join(["v3", "v4", "v5", "v4"][:n]))
                          for n in (0, 1, 2, 4)]
    invalid_selections += [("condition", "v8:u32", "v4,v4,v5"),
        ("unlike-values", "v8:u32", "v3,v4,v6"),
        ("unlike-values-reversed", "v8:u8", "v3,v6,v4"),
        ("result-type", "v8:u8", "v3,v4,v5"),
        ("bool-integer-mix", "v8:bool", "v3,v7,v4"),
        ("readonly-resource", "v8:readbuf", "v3,v0,v0"),
        ("mutable-resource", "v8:mutbuf", "v3,v1,v2"),
        ("void-result", "_", "v3,v4,v5"),
        ("undefined-third", "v8:u32", "v3,v4,v99")]
    for name, output, arguments in invalid_selections:
        source = (selection + f"  {output} = select({arguments})\n  ret(v4)\nend\n").encode()
        add("select-" + name, source, "bool condition, three operands, matching scalar values/result", "rejected")
    seed = simple_source()
    additions = (
        ("parameters-17", parameter_source(17), "16 parameters/arguments"),
        ("blocks-per-function-257", block_source([257]), "256 blocks per function"),
        ("blocks-total-1537", block_source([256] * 6 + [1]), "1536 total blocks"),
        ("functions-129", backward_chain_source() + scalar_function(128).encode(), "128 functions"),
        ("ssa-index-2048", simple_source(variable=2048), "maximum SSA index 2047"),
        ("noncontiguous-function", seed.replace(b"fn f0(", b"fn f1(", 1), "contiguous function numbers"),
        ("entry-signature-name", seed.replace(b"block b0(v0:", b"block b0(v3:", 1), "entry signature names/types"),
        ("unsupported-scalar-u16", seed.replace(b"v3:u32", b"v3:u16").replace(b"-> (u32)", b"-> (u16)"), "supported scalar types and entry return"),
        ("unsupported-effect-combination", seed.replace(b"effects(read,write,trap)", b"effects(trap)"), "fixed declared effects"),
        ("unsupported-module-name", seed.replace(b"v8 selfhost", b"v8 arbitrary"), "fixed input module"),
        ("unsupported-arbitrary-function-name", seed.replace(b"f0(", b"named("), "numeric function identifiers"),
        ("tab-whitespace", seed.replace(b"  v3", b"\tv3"), "ASCII space and LF only"),
        ("crlf-whitespace", seed.replace(b"\n", b"\r\n"), "ASCII space and LF only"),
        ("checked-cast-mode", parameter_source(1).replace(b'"mode":"wrap"', b'"mode":"checked"'), "wrap integer casts only"),
        ("inbound-entry-edge", (HEADER + "  jump b0(v0,v1,v2)\nend\n").encode(), "no inbound entry edges"),
        ("bool-as-integer", (HEADER + '  v3:bool = const() {"value":true}\n'
            '  v4:bool = int.add.wrap(v3,v3)\n  v5:u32 = const() {"value":0}\n  ret(v5)\nend\n').encode(),
            "integer/boolean type distinction"),
        ("unsigned-comparison-type-mismatch", (HEADER +
            '  v3:u8 = const() {"value":1}\n  v4:u32 = const() {"value":1}\n'
            '  v5:bool = compare.eq(v3,v4)\n  v6:u32 = const() {"value":0}\n  ret(v6)\nend\n').encode(),
            "matching unsigned comparison operands"),
        ("integer-op-arity", (HEADER +
            '  v3:u32 = const() {"value":1}\n  v4:u32 = int.add.wrap(v3)\n  ret(v4)\nend\n').encode(),
            "exact operation arity"),
        ("integer-const-arity", seed.replace(b"const()", b"const(v0)"), "zero-argument const"),
        ("boolean-literal-not-integer", seed.replace(b'{"value":7}', b'{"value":true}'), "typed literals"),
        ("integer-literal-not-boolean", (HEADER +
            '  v3:bool = const() {"value":1}\n  v4:u32 = const() {"value":0}\n  ret(v4)\nend\n').encode(),
            "typed literals"),
    )
    for name, source, boundary in additions:
        add(name, source, boundary)
    for op in NEW_INTEGER:
        arguments = "v3" if op == "bit.not" else "v3,v4"
        valid = (HEADER + '  v3:u32 = const() {"value":1}\n'
            '  v4:u32 = const() {"value":1}\n  v5:u32 = ' + op + '(' + arguments + ')\n'
            '  v6:u32 = const() {"value":0}\n  ret(v6)\nend\n').encode()
        token = op.encode() + b"(" + arguments.encode() + b")"
        bad_shapes = {
            "short-arity": valid.replace(token, op.encode() + b"(" + (b"" if op == "bit.not" else b"v3") + b")"),
            "long-arity": valid.replace(token, op.encode() + b"(" + arguments.encode() + b",v4)"),
            "result-type": valid.replace(b"v5:u32", b"v5:u8"),
            "missing-result": valid.replace(b"v5:u32 =", b"_ ="),
            "buffer-operand": valid.replace(token, op.encode() + b"(" + arguments.encode().replace(b"v3", b"v0") + b")"),
            "boolean-operand": valid.replace(b"v3:u32", b"v3:bool").replace(b"v4:u32", b"v4:bool")
                .replace(b"v5:u32", b"v5:bool").replace(b'{"value":1}', b'{"value":true}'),
            "unexpected-attribute": valid.replace(token, token + b' {"mode":"wrap"}'),
        }
        if op in CHECKED_ARITHMETIC:
            bad_shapes["operand-type-mismatch"] = valid.replace(b"v4:u32", b"v4:u8")
        for name, source in bad_shapes.items():
            add(op + "-" + name, source, "exact unsigned operation signature and empty attributes", "rejected")
        for typ, width in WIDTHS.items():
            source = valid.replace(b":u32 =", (":" + typ + " =").encode(), 3)
            source = source.replace(b'{"value":1}', ('{"value":' + str(1 << width) + '}').encode(), 1)
            add(op + "-" + typ + "-literal-overflow", source, "typed literal must fit the operand width", "rejected")
    return list(rows.values())


def shift_trap_cases():
    rows = []
    for typ, width in WIDTHS.items():
        for op in SHIFTS:
            for amount in (width, width + 1):
                a = Assembly()
                value, shift = a.const(typ, 1), a.const(typ, amount)
                result = a.emit(typ, op, [value, shift])
                result = a.emit("u32", "int.cast", [result], {"mode": "wrap"})
                source = (HEADER + a.text() + "  ret(" + result + ")\nend\n").encode()
                rows.append({"id": "shift-trap-" + typ + "-" + op.split(".")[1] + "-" + str(amount),
                             "kind": "shift", "operand_type": typ, "opcode": op, "amount": amount,
                             "expected_output": bytes([0xa5]) * 8, "source": source})
    return rows


def checked_arithmetic_trap_cases():
    """Overflow must abort before a later store; earlier stores are observable."""
    rows = []
    for typ, width in WIDTHS.items():
        mask, high = (1 << width) - 1, 1 << (width - 1)
        inputs = {
            "int.add.checked": ((mask, 1), (1, mask), (high, high), (mask, mask)),
            "int.sub.checked": ((0, 1), (0, mask), (mask - 1, mask), (high - 1, high)),
        }
        for op, operands in inputs.items():
            for index, (left, right) in enumerate(operands):
                for prior_store in ((False, True) if index == 0 else (True,)):
                    a = Assembly()
                    first, second = a.const("usize", 0), a.const("usize", 1)
                    before, after = a.const("u8", 99), a.const("u8", 77)
                    if prior_store:
                        a.effect("buffer.store", ["v1", first, before])
                    lhs, rhs = a.const(typ, left), a.const(typ, right)
                    result = a.emit(typ, op, [lhs, rhs])
                    a.effect("buffer.store", ["v1", second, after])
                    result = a.emit("u32", "int.cast", [result], {"mode": "wrap"})
                    source = (HEADER + a.text() + "  ret(" + result + ")\nend\n").encode()
                    case = {"operand_type": typ, "opcode": op, "arguments": [left, right],
                            "result_type": typ}
                    rows.append({**case, "id": "checked-trap-" + typ + "-" + op.split(".")[1]
                        + "-" + str(index) + ("-prior-store" if prior_store else "-no-prior-store"),
                        "kind": "checked_arithmetic", "prior_store": prior_store, "source": source,
                        "reference_source": scalar_reference_source(case),
                        "expected_output": bytes([99 if prior_store else 0xa5]) + bytes([0xa5]) * 7})
    return rows


def independent_references():
    """Run Core VM before B0 and preserve its disagreement with any oracle."""
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    from hepta.hia_program_runtime import HIAProgramTrap
    scalar = []
    for case in scalar_cases():
        source = scalar_reference_source(case)
        checked = assemble_program(source)
        result = execute_program(checked, "f0", [])
        if result["status"] != "returned" or result["result"] != case["expected"]:
            raise AssertionError({"case": case["id"], "reference": result, "oracle": case["expected"]})
        scalar.append({**case, "reference_source": source.decode(), "core_sha256": checked.sha256,
                       "reference_result": result})
    positives = []
    for fixture in positive_fixtures():
        checked = assemble_program(fixture["source"])
        item = {key: value for key, value in fixture.items() if not isinstance(value, bytes)}
        item.update({"source_bytes": len(fixture["source"]), "source_sha256": digest(fixture["source"]),
                     "core_sha256": checked.sha256, "input_hex": fixture["input"].hex(),
                     "expected_output_hex": fixture["expected_output"].hex()})
        if fixture["kind"] == "boundary":
            scalar_doc = checked.as_dict()
            scalar_doc["functions"][0]["params"] = []
            scalar_doc["functions"][0]["blocks"][0]["params"] = []
            result = execute_program(scalar_doc, "f0", [])
            if result["status"] != "returned" or result["result"] != fixture["expected_result"]:
                raise AssertionError({"case": fixture["id"], "reference": result})
            item.update({"reference_result": result,
                         "reference_change": "remove unused borrowed entry parameters; preserve operations, calls and control flow"})
        elif fixture["kind"] == "buffer" or fixture.get("input_arguments"):
            source = buffer_reference_source(fixture)
            result = execute_program(assemble_program(source), "reference_entry", [])
            if result["status"] != "returned" or result["result"] != list(fixture["expected_output"]):
                raise AssertionError({"case": fixture["id"], "reference": result})
            item.update({"reference_source": source.decode(), "reference_result": result,
                         "reference_change": "add general-Core owned allocation wrapper around unchanged borrowed body"})
        positives.append(item)
    negatives = []
    for fixture in rejected_fixtures():
        try:
            checked = assemble_program(fixture["source"])
        except HIAProgramRejected as exc:
            result = {"status": "rejected", "code": exc.code, "message": str(exc)}
        else:
            result = {"status": "accepted", "core_sha256": checked.sha256}
        expected = fixture["general_core_expected"]
        if expected is not None and result["status"] != expected:
            raise AssertionError({"case": fixture["id"], "reference": result, "expected": expected})
        negatives.append({key: value for key, value in fixture.items() if key != "source"} |
                         {"source_sha256": digest(fixture["source"]), "source_bytes": len(fixture["source"]),
                          "reference_result": result})
    traps = []
    for fixture in shift_trap_cases() + checked_arithmetic_trap_cases():
        checked = assemble_program(fixture["source"])
        if fixture["kind"] == "checked_arithmetic":
            scalar_doc = assemble_program(fixture["reference_source"]).as_dict()
        else:
            scalar_doc = checked.as_dict()
            scalar_doc["functions"][0]["params"] = []
            scalar_doc["functions"][0]["blocks"][0]["params"] = []
        try:
            result = execute_program(scalar_doc, "f0", [])
        except HIAProgramTrap as exc:
            result = {"status": "trapped", "trap": exc.code, "message": str(exc)}
        if result.get("status") != "trapped" or result.get("trap") != "overflow":
            raise AssertionError({"case": fixture["id"], "reference": result})
        traps.append({key: value for key, value in fixture.items() if not isinstance(value, bytes)} |
                     {"core_sha256": checked.sha256, "source_sha256": digest(fixture["source"]),
                      "arithmetic_reference_source": fixture.get("reference_source", b"").decode(),
                      "expected_native_output_hex": fixture["expected_output"].hex(),
                      "memory_ordering_reference": "native shared output directly observes prior store and absence of later store",
                      "reference_result": result})
    return {"scalar": scalar, "positive": positives, "negative": negatives, "traps": traps}


def semantic_contract(contract):
    return {key: value for key, value in contract.items() if key != "source_identity"}


def coverage_manifest():
    from tools.generate_hia_selfhost import document, WORDS
    from tools.hia_selfhost_contract import support_contract
    from hepta.hia_agent_assembly import render_assembly
    from hepta.hia_opcodes import OPCODES
    contract = support_contract()
    doc, names = document()
    compiler = (ROOT / "examples/hia_bootstrap/selfhost.hiaasm").read_bytes()
    if render_assembly(doc).encode() != compiler:
        raise AssertionError("authoring map is not the checked-in HIA compiler")
    supported = sorted(word for word in WORDS if word in OPCODES)
    if supported != list(INPUT_OPCODES):
        raise AssertionError("coverage inventory differs from actual HIA keyword/opcode set")
    rules = {
        "scalar_types": (["read_type", "instruction", "normalize"], ["scalar-*", "boolean", "cast"]),
        "resources": (["args", "edge", "operation"], ["borrowed-buffer-operations", "existing-readonly-*", "swap-*"]),
        "integer_operations": (["instruction", "operation", "checked_integer", "select_scalar", "normalize"],
            ["scalar-*", "dynamic-integer-*", "boolean", "cast", "shift-trap-*", "checked-trap-*",
             "bit.not-*", "int.add.checked-*", "int.sub.checked-*", "select-*"]),
        "control_flow": (["parse_block", "edge", "check_graph"], ["boolean", "blocks-*", "inbound-entry-edge", "existing-unreachable-block"]),
        "calls": (["instruction", "args", "check_calls", "copy_argument"], ["parameters-16", "parameters-17", "call-*"]),
        "recursion": (["instruction", "parse_block", "check_calls"], ["recursion-*", "tail-*"]),
        "owned_resources": (["read_type", "instruction", "operation"], []),
        "general_core_checker": (["compile", "read_type", "next_token", "instruction"], ["unsupported-*"]),
        "successor_output": (["wrapper", "operation", "relocation", "fix_all"], ["B1", "B2", "B3", "M1", "M2", "M3"]),
        "successor_object_output": (["elf_begin", "elf_finish", "elf_section", "align8"], []),
        "general_object_linking": (["compile", "elf_finish"], []),
    }
    existing = {
        "resources": ["tools.hia_selfhost_resources.qualify_resources",
                      "tests.test_hia_selfhost.SelfhostNativeTests.test_native_edges_reject_readonly_duplicates_but_calls_keep_legal_aliases"],
        "control_flow": ["tools.qualify_hia_selfhost.qualify"],
        "calls": ["tools.hia_selfhost_cases.backward_chain_source", "tools.qualify_hia_selfhost.qualify"],
        "recursion": ["tools.hia_selfhost_tailcalls.qualify_tailcalls"],
        "successor_output": ["tools.qualify_hia_selfhost.qualify"],
        "successor_object_output": ["tools.qualify_hia_selfhost.qualify_elf_outputs"],
        "general_object_linking": [],
    }
    features = []
    for row in contract["support"]:
        functions, witnesses = rules[row["area"]]
        features.append({**row, "hia_functions": {name: names[name] for name in functions},
                         "new_witnesses": witnesses, "existing_evidence": existing.get(row["area"], [])})
    row_cases = scalar_cases()
    negative = rejected_fixtures()
    return {
        "schema": "hepta.hia.selfhost-language-coverage.v1", "profile": PROFILE,
        "claims": {"inventory_covers_declared_v8_features": True,
                   "finite_witnesses_are_all_input_correctness_proof": False,
                   "whole_HIA_language_self_hosted": False,
                   "compiler_correctness_formally_proved": False,
                   "this_inventory_is_execution_evidence": False},
        "source": {
            "compiler": {"path": "examples/hia_bootstrap/selfhost.hiaasm", "sha256": digest(compiler)},
            "authoring_map": {"path": "tools/generate_hia_selfhost.py",
                "sha256": digest((ROOT / "tools/generate_hia_selfhost.py").read_bytes())},
            "semantic_support_sha256": digest(canonical(semantic_contract(contract))),
            "support_projection_omits": ["source_identity"],
        },
        "input_opcodes": supported, "general_core_opcode_count": len(OPCODES),
        "general_core_opcodes_outside_v8": sorted(set(OPCODES) - set(supported)),
        "input_types": [*WIDTHS, "bool", "readbuf", "mutbuf"],
        "features": features,
        "syntax": {"contract": contract["syntax"],
                   "hia_functions": {name: names[name] for name in (
                       "compile", "parse_function", "parse_params", "parse_block", "define",
                       "variable", "next_token", "decimal", "adjacent", "separated", "expect")},
                   "new_positive": ["optional-ascii-spaces", "ssa-index-2047"],
                   "new_negative": [row["id"] for row in negative if row["id"].startswith(
                       ("existing-", "noncontiguous-", "entry-", "unsupported-", "tab-", "crlf-", "ssa-"))]},
        "limits": {"contract": contract["limits"],
                   "new_boundaries": ["parameters-16", "parameters-17", "blocks-per-function-256",
                                      "blocks-per-function-257", "blocks-total-1536", "blocks-total-1537",
                                      "functions-129", "ssa-index-2047", "ssa-index-2048",
                                      "source-bytes-1048576"],
                   "existing_evidence": ["tools.hia_selfhost_cases.backward_chain_source",
                       "tools.hia_selfhost_capacity.qualify_capacity",
                       "tools.hia_selfhost_tailcalls.qualify_tailcalls",
                       "tools.qualify_hia_selfhost.qualify"],
                   "unreachable_relocation_ceiling": {
                       "configured": contract["limits"]["relative_relocations"],
                       "derived_maximum_with_other_limits": contract["capacity_derivation"]["relative_relocations_upper_bound"]},
                   "transport_limit": "ordinary child rejects source/output sizes above 1 MiB before native entry; no larger native-call claim"},
        "scalar_witnesses": {
            "count": len(row_cases), "groups": {group: sum(row["group"] == group for row in row_cases)
                for group in dict.fromkeys(row["group"] for row in row_cases)},
            "unsigned_widths": WIDTHS, "wrap_cast_pairs": [[a, b] for a in WIDTHS for b in WIDTHS],
            "boolean_inputs": [[a, b] for a in (False, True) for b in (False, True)],
            "specification_sha256": digest(canonical(row_cases)),
            "observation": "eight little-endian output bytes per scalar result, including all 64 bits",
            "dynamic_integer_witnesses": "each new integer operation reads all operand bytes from the runtime source buffer",
            "reference": "independent general Core VM plus Python integer/boolean oracle, executed before B0"},
        "rejected_inputs": [{"id": row["id"], "boundary": row["boundary"],
                            "general_core_expected": row["general_core_expected"],
                            "source_sha256": digest(row["source"])} for row in negative],
        "checked_shift_traps": [{"id": row["id"], "type": row["operand_type"], "opcode": row["opcode"],
                                "amount": row["amount"]} for row in shift_trap_cases()],
        "checked_arithmetic_traps": [{"id": row["id"], "type": row["operand_type"], "opcode": row["opcode"],
            "arguments": row["arguments"], "prior_store": row["prior_store"],
            "expected_native_output_hex": row["expected_output"].hex(),
            "source_sha256": digest(row["source"])} for row in checked_arithmetic_trap_cases()],
        "bootstrap": {"required": contract["required_replay"],
                      "dependency_closure": "support source_identity includes this test and this inventory; B0 receipt records actual loaded seed modules",
                      "successors": "stdlib-only disposable child; all input translation is executed HIA",
                      "cold_replay": "tools/replay_hia_selfhost_cold.py",
                      "cold_replay_boundary": "source/process/cache isolation; same host CPython, standard library, GNU ld, libc, kernel and hardware"},
        "run": {"command": "python -B tests/test_hia_selfhost_language_coverage.py --output <new-report.json>",
                "unittest_evidence_environment": "HIA_SELFHOST_LANGUAGE_EVIDENCE",
                "retained": ["B0 and B1/B2/B3", "M1/M2/M3", "exact compiler and fixture input bytes",
                             "reference observations", "native output bytes", "raw child stdout/stderr",
                             "native request and receipt JSON", "source closure and runtime identities"],
                "failure_report": "report is written with status FAIL and an error before raising"},
    }


def validate_inventory():
    actual = json.loads((ROOT / COVERAGE_PATH).read_text())
    expected = coverage_manifest()
    if actual != expected:
        raise AssertionError("language inventory is stale; regenerate from coverage_manifest after review")
    from tools.hia_selfhost_contract import SOURCE_FILES
    if SELF_PATH not in SOURCE_FILES or COVERAGE_PATH not in SOURCE_FILES:
        raise AssertionError("coverage evidence inputs are outside the pinned source closure")
    return actual


def qualify_language(output):
    from tools.hia_selfhost_contract import validate_contract
    from tools.qualify_hia_selfhost import (CAPACITY, INVALID, SOURCE, build_seed, compile_stage,
                                           invoke, mutate_compiler, source_manifest)
    if not NATIVE:
        raise RuntimeError("native language qualification requires Linux x86-64 and GNU ld")
    requested = Path(output)
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    if any(path.is_symlink() for path in (requested, *requested.parents)):
        raise ValueError("language qualification output cannot use symbolic links")
    if requested.exists():
        raise ValueError("language qualification requires a fresh report")
    output = requested.resolve()
    directory = output.with_suffix(".evidence")
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.selfhost-language-qualification.v1", "profile": PROFILE,
              "status": "FAIL", "checks": {}, "positive": [], "negative": [], "traps": [],
              "generations": [], "modified_generations": [],
              "claims": {"whole_HIA_language_self_hosted": False,
                         "compiler_correctness_formally_proved": False,
                         "finite_witnesses_prove_all_inputs": False}}
    try:
        contract = validate_contract()
        inventory = validate_inventory()
        before = source_manifest()
        report.update({"source_manifest": before,
                       "inventory_sha256": digest((ROOT / COVERAGE_PATH).read_bytes()),
                       "semantic_support_sha256": inventory["source"]["semantic_support_sha256"],
                       "runtime": {"python": sys.version, "executable": str(Path(sys.executable).resolve()),
                                   "executable_sha256": digest(Path(sys.executable).read_bytes()),
                                   "platform": platform.platform()}})
        reference = independent_references()
        write_json(directory / "independent-reference.json", reference)
        report["reference"] = {"path": str(directory / "independent-reference.json"),
            "sha256": digest((directory / "independent-reference.json").read_bytes()),
            "scalar_cases": len(reference["scalar"]), "before_B0": True}
        checks = report["checks"]
        checks["reference_vm_matches_all_scalar_oracles"] = True
        checks["inventory_matches_actual_compiler_source"] = True
        compiler_source = SOURCE.read_bytes()
        (directory / "compiler.hiaasm").write_bytes(compiler_source)
        seed, seed_receipt = build_seed(directory, compiler_source)
        report["seed"] = seed_receipt
        predecessor = seed
        for generation in ("B1", "B2", "B3"):
            predecessor, receipt = compile_stage(directory, generation, predecessor, compiler_source,
                image_format="seed-shared" if generation == "B1" else "flat-x86-64",
                workspace_fill=0x5a if generation == "B3" else 0)
            report["generations"].append(receipt)
        b3 = predecessor
        modified = mutate_compiler(compiler_source)
        (directory / "compiler-mutated.hiaasm").write_bytes(modified)
        for generation in ("M1", "M2", "M3"):
            predecessor, receipt = compile_stage(directory, generation, predecessor, modified)
            report["modified_generations"].append(receipt)
        m3 = predecessor
        original_hashes = [row["produced_sha256"] for row in report["generations"]]
        modified_hashes = [row["produced_sha256"] for row in report["modified_generations"]]
        checks["original_fixed_point"] = len(set(original_hashes)) == 1
        checks["modified_fixed_point"] = (modified_hashes[0] != modified_hashes[1]
            and modified_hashes[1] == modified_hashes[2] and modified_hashes[2] != original_hashes[2])
        checks["source_bound_before_execution"] = contract["profile"] == PROFILE
        positive = positive_fixtures()
        negative = rejected_fixtures()
        traps = shift_trap_cases() + checked_arithmetic_trap_cases()
        for label, compiler in (("B3", b3), ("M3", m3)):
            for fixture in positive:
                name = label + "-" + fixture["id"]
                image, build = compile_stage(directory, name + "-build", compiler, fixture["source"])
                result, observed = invoke(directory, name, image, fixture["input"],
                    capacity=fixture["capacity"], workspace_size=fixture["workspace_size"])
                good = (result.get("status") == "returned" and result.get("abi_status") == 0
                    and result.get("core_u32") == fixture["expected_result"]
                    and result.get("source_unchanged") and not result.get("forbidden_compiler_modules_loaded")
                    and observed == fixture["expected_output"])
                checks[name] = bool(good)
                report["positive"].append({"compiler": label, "id": fixture["id"],
                    "case_ids": fixture["case_ids"], "build": build, "execution": result,
                    "expected_result": fixture["expected_result"],
                    "expected_output_sha256": digest(fixture["expected_output"]),
                    "observed_output_sha256": digest(observed)})
            for fixture in negative:
                name = label + "-reject-" + fixture["id"]
                result, observed = invoke(directory, name, compiler, fixture["source"], capacity=512)
                good = (result.get("status") == "returned" and result.get("abi_status") == 0
                    and result.get("core_u32") == INVALID and result.get("source_unchanged")
                    and result.get("output_unchanged") and observed == bytes([0xa5]) * 512
                    and not result.get("forbidden_compiler_modules_loaded"))
                checks[name] = bool(good)
                report["negative"].append({"compiler": label, "id": fixture["id"],
                                          "execution": result, "transactional_rejection": bool(good)})
            for fixture in traps:
                name = label + "-" + fixture["id"]
                image, build = compile_stage(directory, name + "-build", compiler, fixture["source"])
                result, observed = invoke(directory, name, image, b"", capacity=8, workspace_size=0,
                                           observe_trap_writes=True)
                good = (result.get("status") == "child_failed" and result.get("returncode") == -4
                    and result.get("shared_output_observation", {}).get("available")
                    and observed == fixture["expected_output"])
                checks[name] = bool(good)
                report["traps"].append({"compiler": label, "id": fixture["id"], "kind": fixture["kind"],
                                        "prior_store": fixture.get("prior_store", False),
                                        "expected_output_hex": fixture["expected_output"].hex(),
                                        "observed_output_hex": observed.hex(),
                                        "build": build, "execution": result})
        checks["source_closure_unchanged"] = source_manifest() == before
        report["counts"] = {"scalar_witnesses": len(reference["scalar"]),
            "positive_programs_per_compiler": len(positive),
            "rejections_per_compiler": len(negative), "shift_traps_per_compiler": len(shift_trap_cases()),
            "checked_arithmetic_traps_per_compiler": len(checked_arithmetic_trap_cases()),
            "traps_per_compiler": len(traps),
            "compilers": 2, "checks_total": len(checks), "checks_passed": sum(checks.values())}
        report["status"] = "SELFHOST_LANGUAGE_COVERAGE_PASS" if all(checks.values()) else "FAIL"
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        report["wall_elapsed_ns"] = time.monotonic_ns() - started
        write_json(output, report)
    return report


class SelfhostLanguageSourceTests(unittest.TestCase):
    def test_inventory_matches_supported_features_actual_hia_and_source_closure(self):
        manifest = validate_inventory()
        self.assertEqual(manifest["profile"], PROFILE)
        self.assertEqual(len(manifest["input_opcodes"]), 28)
        self.assertIn("select", manifest["input_opcodes"])
        self.assertEqual(manifest["general_core_opcode_count"], 50)
        self.assertFalse(manifest["claims"]["whole_HIA_language_self_hosted"])
        self.assertFalse(manifest["claims"]["compiler_correctness_formally_proved"])

    def test_every_supported_integer_opcode_and_width_has_independent_inputs(self):
        rows = scalar_cases()
        for typ in WIDTHS:
            observed = {row["opcode"] for row in rows if row["operand_type"] == typ}
            self.assertTrue(set(("const", *BINARY_INTEGER, *NEW_INTEGER, *SHIFTS, *COMPARISONS, "int.cast", "select")) <= observed)
        self.assertEqual({(row["operand_type"], row["result_type"]) for row in rows if row["opcode"] == "int.cast"},
                         {(a, b) for a in WIDTHS for b in WIDTHS})
        for op in ("bool.and", "bool.or"):
            self.assertEqual({tuple(row["arguments"]) for row in rows if row["opcode"] == op},
                             {(a, b) for a in (False, True) for b in (False, True)})

    def test_select_covers_each_scalar_type_and_changing_inputs(self):
        rows = [row for row in scalar_cases() if row["opcode"] == "select"]
        self.assertEqual(len(rows), 40)
        for typ in (*WIDTHS, "bool"):
            selected = [row for row in rows if row["operand_type"] == typ]
            self.assertEqual(len(selected), 8)
            self.assertEqual({row["arguments"][0] for row in selected}, {False, True})
        self.assertEqual({tuple(row["arguments"]) for row in rows if row["operand_type"] == "bool"},
                         {(c, a, b) for c in (False, True) for a in (False, True) for b in (False, True)})
        fixtures = select_input_fixtures()
        self.assertEqual(len(fixtures), 28)
        for typ in (*WIDTHS, "bool"):
            selected = [row for row in fixtures if row["id"].startswith("select-input-" + typ + "-")]
            self.assertEqual(len({row["source"] for row in selected}), 1)
            self.assertGreater(len({row["input"] for row in selected}), 1)
            self.assertGreater(len({row["expected_output"] for row in selected}), 1)

    def test_independent_core_vm_agrees_with_scalar_buffer_and_boundary_oracles(self):
        reference = independent_references()
        # The original 568 plus 92 integer and 40 select witnesses.
        self.assertEqual(len(reference["scalar"]), 700)
        self.assertTrue(all(row["reference_result"]["status"] == "trapped" for row in reference["traps"]))
        self.assertTrue(any(row["reference_result"]["status"] == "accepted" for row in reference["negative"]))
        self.assertTrue(any(row["reference_result"]["status"] == "rejected" for row in reference["negative"]))

    def test_native_fixtures_cover_all_input_opcodes_and_observe_full_width(self):
        from hepta.hia_agent_assembly import assemble_program
        observed = set()
        fixtures = positive_fixtures()
        for fixture in fixtures:
            checked = assemble_program(fixture["source"])
            observed.update(op["op"] for fn in checked.as_dict()["functions"] for block in fn["blocks"] for op in block["ops"])
            if fixture["kind"] == "scalar":
                self.assertEqual(fixture["capacity"], len(fixture["case_ids"]) * 8)
        self.assertEqual(observed, set(INPUT_OPCODES))
        self.assertTrue(any(fixture["capacity"] > 128 for fixture in fixtures))

    def test_rejections_retain_invalid_core_and_valid_outside_profile_distinction(self):
        reference = independent_references()
        rows = {row["id"]: row for row in reference["negative"]}
        for name in ("recursion-non-tail-direct-recursion", "recursion-mutual-recursion",
                     "recursion-unreachable-cycle", "unsupported-module-name"):
            self.assertEqual(rows[name]["reference_result"]["status"], "accepted")
        for name in ("integer-op-arity", "unsigned-comparison-type-mismatch", "swap-readonly"):
            self.assertEqual(rows[name]["reference_result"]["status"], "rejected")
        for op in NEW_INTEGER:
            self.assertTrue(all(row["reference_result"]["status"] == "rejected"
                for row in rows.values() if row["id"].startswith(op + "-")))

    def test_checked_arithmetic_covers_width_boundaries_and_both_write_orders(self):
        rows = checked_arithmetic_trap_cases()
        self.assertEqual(len(rows), 40)
        for typ, width in WIDTHS.items():
            for op in CHECKED_ARITHMETIC:
                cases = [row for row in rows if row["operand_type"] == typ and row["opcode"] == op]
                self.assertEqual(len(cases), 5)
                self.assertEqual({row["prior_store"] for row in cases}, {False, True})
                for row in cases:
                    a, b = row["arguments"]
                    result = a + b if op == "int.add.checked" else a - b
                    self.assertFalse(0 <= result < (1 << width))
                    self.assertEqual(row["expected_output"][1:], bytes([0xa5]) * 7)

    def test_language_inventory_does_not_claim_unavailable_whole_v8_or_formal_proof(self):
        manifest = coverage_manifest()
        self.assertFalse(manifest["claims"]["finite_witnesses_are_all_input_correctness_proof"])
        self.assertFalse(manifest["claims"]["this_inventory_is_execution_evidence"])
        unsupported = {row["area"] for row in manifest["features"] if row["status"] == "not_implemented"}
        self.assertEqual(unsupported, {"owned_resources", "general_core_checker", "general_object_linking"})
        self.assertEqual(manifest["limits"]["unreachable_relocation_ceiling"],
                         {"configured": 12000, "derived_maximum_with_other_limits": 11265})


@unittest.skipUnless(NATIVE, "Linux x86-64 and GNU ld seed linker required")
class SelfhostLanguageNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retained = os.environ.get("HIA_SELFHOST_LANGUAGE_EVIDENCE")
        cls.temporary = None if retained else tempfile.TemporaryDirectory(prefix="hia-language-coverage-")
        cls.output = Path(retained) if retained else Path(cls.temporary.name) / "language.json"
        cls.report = qualify_language(cls.output)

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:
            cls.temporary.cleanup()

    def test_original_and_modified_compilers_are_real_fixed_points(self):
        self.assertTrue(self.report["checks"]["original_fixed_point"])
        self.assertTrue(self.report["checks"]["modified_fixed_point"])
        self.assertTrue(self.report["checks"]["source_closure_unchanged"])

    def test_every_positive_program_runs_under_both_hia_compilers(self):
        self.assertEqual(self.report["status"], "SELFHOST_LANGUAGE_COVERAGE_PASS", self.report["checks"])
        groups = {row["id"] for row in self.report["positive"]}
        for group in groups:
            self.assertEqual({row["compiler"] for row in self.report["positive"] if row["id"] == group}, {"B3", "M3"})
        self.assertEqual(self.report["reference"]["scalar_cases"], 700)

    def test_negative_inputs_are_transactionally_rejected_by_both_compilers(self):
        self.assertTrue(self.report["negative"])
        self.assertTrue(all(row["transactional_rejection"] for row in self.report["negative"]))

    def test_invalid_checked_shifts_trap_with_native_output_preserved(self):
        rows = [row for row in self.report["traps"] if row["kind"] == "shift"]
        self.assertEqual(len(rows), 32)
        for row in rows:
            self.assertEqual(row["execution"]["returncode"], -4)
            self.assertTrue(row["execution"]["shared_output_observation"]["unchanged"])

    def test_checked_arithmetic_traps_before_later_writes_and_preserves_prior_writes(self):
        rows = [row for row in self.report["traps"] if row["kind"] == "checked_arithmetic"]
        self.assertEqual(len(rows), 80)
        for row in rows:
            self.assertEqual(row["execution"]["returncode"], -4)
            self.assertEqual(row["observed_output_hex"], row["expected_output_hex"])
            self.assertEqual(row["execution"]["shared_output_observation"]["unchanged"], not row["prior_store"])

    def test_new_integer_operations_use_runtime_input_under_both_compilers(self):
        for typ in WIDTHS:
            rows = [row for row in self.report["positive"] if row["id"] == "dynamic-integer-" + typ]
            self.assertEqual({row["compiler"] for row in rows}, {"B3", "M3"})
            for row in rows:
                self.assertGreater(row["execution"]["input_bytes"], 0)
                self.assertEqual(row["observed_output_sha256"], row["expected_output_sha256"])

    def test_select_uses_changing_inputs_and_full_width_output_under_both_compilers(self):
        for typ in (*WIDTHS, "bool"):
            rows = [row for row in self.report["positive"]
                    if row["id"].startswith("select-input-" + typ + "-")]
            for compiler in ("B3", "M3"):
                observed = [row for row in rows if row["compiler"] == compiler]
                self.assertEqual(len(observed), 8 if typ == "bool" else 5)
                for row in observed:
                    self.assertGreater(row["execution"]["input_bytes"], 0)
                    self.assertEqual(row["observed_output_sha256"], row["expected_output_sha256"])

    def test_all_generations_and_raw_evidence_are_retained(self):
        directory = self.output.with_suffix(".evidence")
        for generation in ("B1", "B2", "B3", "M1", "M2", "M3"):
            self.assertTrue((directory / (generation + ".image.bin")).is_file())
            self.assertTrue((directory / (generation + ".stdout.log")).is_file())
            self.assertTrue((directory / (generation + ".stderr.log")).is_file())
        self.assertTrue((directory / "B0.receipt.json").is_file())
        self.assertTrue((directory / "independent-reference.json").is_file())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--generate-inventory", action="store_true",
                        help="write feature inventory only; does not regenerate the support source lock")
    args = parser.parse_args()
    if args.generate_inventory:
        write_json(ROOT / COVERAGE_PATH, coverage_manifest())
        print(json.dumps({"inventory": COVERAGE_PATH, "sha256": digest((ROOT / COVERAGE_PATH).read_bytes())}))
        return
    if args.output is None:
        parser.error("--output is required for retained native qualification")
    result = qualify_language(args.output)
    print(json.dumps({"status": result["status"], "output": str(args.output),
                      "counts": result.get("counts"), "error": result.get("error")}, sort_keys=True))
    raise SystemExit(0 if result["status"] == "SELFHOST_LANGUAGE_COVERAGE_PASS" else 1)


if __name__ == "__main__":
    main()
